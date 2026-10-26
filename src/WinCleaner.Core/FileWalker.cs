using System.IO.Enumeration;

namespace WinCleaner.Core;

/// <summary>Size, file count and newest change time of a file or folder tree.</summary>
public readonly record struct TreeSize(long Bytes, int Files, DateTime NewestWriteUtc);

/// <summary>
/// Fast read-only walks with the .NET enumerator (one NtQueryDirectoryFile
/// call per 64 KB of entries). Junctions, symbolic links and mount points are
/// never entered, cloud placeholders count as zero bytes.
/// </summary>
public static class FileWalker
{
    private const FileAttributes CloudOnly = (FileAttributes)0x0004_1000 | (FileAttributes)0x0040_0000;

    public static EnumerationOptions Options(bool recurse) => new()
    {
        RecurseSubdirectories = recurse,
        IgnoreInaccessible = true,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
        BufferSize = 64 * 1024,
    };

    public static bool IsLocalOnly(FileAttributes attributes) => (attributes & CloudOnly) == 0;

    /// <summary>Measures a file or a folder with everything below it.</summary>
    public static TreeSize Measure(string path, CancellationToken cancellation = default)
    {
        FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        if (!info.Exists) return default;
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) return new TreeSize(0, 0, info.LastWriteTimeUtc);
        if (info is FileInfo file)
            return new TreeSize(IsLocalOnly(file.Attributes) ? file.Length : 0, 1, file.LastWriteTimeUtc);

        long bytes = 0;
        int files = 0;
        DateTime newest = info.LastWriteTimeUtc;
        var enumerable = new FileSystemEnumerable<(long Size, bool IsFile, DateTime Write)>(path,
            (ref FileSystemEntry e) => (e.IsDirectory || !IsLocalOnly(e.Attributes) ? 0 : e.Length, !e.IsDirectory, e.LastWriteTimeUtc.UtcDateTime),
            Options(recurse: true))
        {
            ShouldRecursePredicate = (ref FileSystemEntry e) => (e.Attributes & FileAttributes.ReparsePoint) == 0,
        };
        foreach (var (size, isFile, write) in enumerable)
        {
            cancellation.ThrowIfCancellationRequested();
            bytes += size;
            if (isFile) files++;
            if (write > newest) newest = write;
        }
        return new TreeSize(bytes, files, newest);
    }

    /// <summary>Direct children of a folder: (full path, attributes, length, last write).</summary>
    public static IEnumerable<(string Path, FileAttributes Attributes, long Length, DateTime LastWriteUtc)> Children(string folder)
    {
        if (!Directory.Exists(folder)) return [];
        return new FileSystemEnumerable<(string, FileAttributes, long, DateTime)>(folder,
            (ref FileSystemEntry e) => (e.ToFullPath(), e.Attributes, e.IsDirectory ? 0 : e.Length, e.LastWriteTimeUtc.UtcDateTime),
            Options(recurse: false));
    }

    /// <summary>Name match with * and ? wildcards, ignoring case.</summary>
    public static bool Matches(string name, string pattern) =>
        FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true);

    public static bool HasWildcard(string s) => s.AsSpan().IndexOfAny('*', '?') >= 0;
}
