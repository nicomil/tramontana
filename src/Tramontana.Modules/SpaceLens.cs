using System.Collections.Concurrent;
using Microsoft.Win32.SafeHandles;
using Tramontana.Core;

namespace Tramontana.Modules;

/// <summary>One file or folder in the disk map.</summary>
public sealed class DiskNode
{
    public required string Path { get; init; }
    public required string Name { get; init; }
    /// <summary>Bytes allocated on disk (cloud placeholders and extra hard links count zero).</summary>
    public required long Size { get; init; }
    public required bool IsDirectory { get; init; }
    /// <summary>True for the block that groups the small files of a folder.</summary>
    public bool IsAggregate { get; init; }
    /// <summary>A folder that could not be read (its size is unknown).</summary>
    public bool IsUnreadable { get; init; }
    public int FileCount { get; init; }
    public DateTime LastWriteUtc { get; init; }
    /// <summary>Sorted by size, biggest first.</summary>
    public IReadOnlyList<DiskNode> Children { get; init; } = [];
}

/// <summary>Counts scanned files from many threads, for the progress label.</summary>
public sealed class ScanCounter
{
    private long _files;
    private long _bytes;
    public void Add(long files, long bytes)
    {
        Interlocked.Add(ref _files, files);
        Interlocked.Add(ref _bytes, bytes);
    }
    public (long Files, long Bytes) Snapshot => (Interlocked.Read(ref _files), Interlocked.Read(ref _bytes));
}

/// <summary>
/// Builds the size map of a folder or a whole drive.
///
/// Folders are opened relative to their parent handle and listed 64 KB at a
/// time with file ids, in parallel near the top of the tree. Junctions and
/// symbolic links are not entered (Windows has several, like "Documents and
/// Settings"), hard links are counted once (C:\Windows\WinSxS is mostly hard
/// links to System32), and the allocated size is used, so compressed and
/// cloud files show what they really take. Files smaller than
/// <see cref="MinimumFileSize"/> are merged into one block per folder.
/// </summary>
public sealed class SpaceLensScanner
{
    public long MinimumFileSize { get; init; } = 5_000_000;
    public int ParallelDepth { get; init; } = 20;

    private readonly ConcurrentDictionary<UInt128, byte> _seenLinks = new();

    public DiskNode Scan(string root, ScanCounter? counter = null, CancellationToken cancellation = default)
    {
        root = KnownPaths.Long(root);
        counter ??= new ScanCounter();
        using var handle = PinnedFileSystem.OpenDirectoryPath(root);
        return ScanDirectory(handle, root, System.IO.Path.GetFileName(root.TrimEnd('\\')) is { Length: > 0 } n ? n : root,
            0, counter, cancellation);
    }

    private DiskNode ScanDirectory(SafeFileHandle handle, string path, string name, int depth, ScanCounter counter,
        CancellationToken cancellation)
    {
        List<DirectoryEntry> entries;
        try
        {
            entries = PinnedFileSystem.Enumerate(handle, withIds: true);
        }
        catch (IOException)
        {
            return new DiskNode { Path = path, Name = name, Size = 0, IsDirectory = true, IsUnreadable = true };
        }

        var nodes = new List<DiskNode>();
        var folders = new List<DirectoryEntry>();
        long smallSize = 0;
        int smallCount = 0;
        int fileCount = 0;
        long newest = 0;

        foreach (var entry in entries)
        {
            if (cancellation.IsCancellationRequested) break;
            if (entry.IsReparsePoint) continue;
            if (entry.IsDirectory) { folders.Add(entry); continue; }

            long size = entry.AllocationSize;
            // A file with several names (hard links) is counted the first time it is seen.
            if (size > 0 && entry.FileId != default && !_seenLinks.TryAdd(entry.FileId, 0)) size = 0;
            counter.Add(1, size);
            fileCount++;
            if (entry.LastWriteTimeUtc > newest) newest = entry.LastWriteTimeUtc;
            if (size >= MinimumFileSize)
            {
                nodes.Add(new DiskNode
                {
                    Path = System.IO.Path.Combine(path, entry.Name), Name = entry.Name, Size = size,
                    IsDirectory = false, FileCount = 1, LastWriteUtc = entry.LastWriteUtc,
                });
            }
            else
            {
                smallSize += size;
                smallCount++;
            }
        }

        DiskNode ScanChild(DirectoryEntry entry)
        {
            string childPath = System.IO.Path.Combine(path, entry.Name);
            try
            {
                using var child = PinnedFileSystem.OpenSubdirectory(handle, entry.Name);
                return ScanDirectory(child, childPath, entry.Name, depth + 1, counter, cancellation);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return new DiskNode { Path = childPath, Name = entry.Name, Size = 0, IsDirectory = true, IsUnreadable = true };
            }
        }

        if (depth < ParallelDepth && folders.Count > 1)
        {
            var results = new DiskNode[folders.Count];
            Parallel.For(0, folders.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(4, Environment.ProcessorCount * 2) },
                (i, state) =>
                {
                    if (cancellation.IsCancellationRequested) { state.Stop(); return; }
                    results[i] = ScanChild(folders[i]);
                });
            nodes.AddRange(results.Where(r => r is not null));
        }
        else
        {
            foreach (var folder in folders)
            {
                if (cancellation.IsCancellationRequested) break;
                nodes.Add(ScanChild(folder));
            }
        }

        if (smallCount > 0)
        {
            nodes.Add(new DiskNode
            {
                Path = System.IO.Path.Combine(path, "*"), Name = $"{smallCount} file piccoli", Size = smallSize,
                IsDirectory = false, IsAggregate = true, FileCount = smallCount,
                LastWriteUtc = newest > 0 ? DateTime.FromFileTimeUtc(newest) : default,
            });
        }
        nodes.RemoveAll(n => n.Size == 0 && !n.IsUnreadable);
        nodes.Sort((a, b) => b.Size.CompareTo(a.Size));
        return new DiskNode
        {
            Path = path, Name = name, Size = nodes.Sum(n => n.Size), IsDirectory = true,
            FileCount = nodes.Sum(n => n.IsDirectory ? n.FileCount : n.FileCount), Children = nodes,
            LastWriteUtc = nodes.Count > 0 ? nodes.Max(n => n.LastWriteUtc) : default,
        };
    }

    /// <summary>Total and free bytes of the drive holding <paramref name="path"/>.</summary>
    public static (long Total, long Free) DriveSpace(string path)
    {
        var drive = new DriveInfo(System.IO.Path.GetPathRoot(path)!);
        return (drive.TotalSize, drive.AvailableFreeSpace);
    }
}
