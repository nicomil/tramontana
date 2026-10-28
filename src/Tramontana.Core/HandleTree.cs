using Microsoft.Win32.SafeHandles;
using static Tramontana.Core.Native.NativeMethods;

namespace Tramontana.Core;

/// <summary>What happened while measuring or deleting a tree.</summary>
public sealed class TreeStats
{
    /// <summary>Bytes freed (or that would be freed).</summary>
    public long Bytes;
    /// <summary>Files and folders removed.</summary>
    public int Removed;
    /// <summary>Items skipped because another program has them open.</summary>
    public int InUse;
    /// <summary>Items that could not be removed for another reason.</summary>
    public int Failed;
    public string? FirstError;

    internal void Fail(Exception e)
    {
        Failed++;
        FirstError ??= e.Message;
    }
}

/// <summary>
/// Measures and deletes folder trees through handles (see <see cref="PinnedFileSystem"/>).
/// Junctions, symbolic links and mount points inside the tree are removed as
/// links: what they point to is never listed, measured or deleted.
/// </summary>
public static class HandleTree
{
    public const uint ItemAccess = DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL;
    private const int MaxDepth = 400;

    /// <summary>Size of an open item and everything below it, without following links.</summary>
    public static long Measure(SafeFileHandle item, CancellationToken cancellation = default)
    {
        var info = PinnedFileSystem.GetInfo(item);
        if (info.IsReparsePoint) return 0;
        if (!info.IsDirectory) return LocalSize(item, info);
        using var list = PinnedFileSystem.ReOpen(item, PinnedFileSystem.DirectoryReadAccess);
        return MeasureDirectory(list, 0, cancellation);
    }

    private static long MeasureDirectory(SafeFileHandle directory, int depth, CancellationToken cancellation)
    {
        if (depth > MaxDepth) return 0;
        long total = 0;
        List<DirectoryEntry> entries;
        try { entries = PinnedFileSystem.Enumerate(directory); }
        catch (IOException) { return 0; }
        foreach (var entry in entries)
        {
            cancellation.ThrowIfCancellationRequested();
            if (entry.IsReparsePoint) continue;
            if (entry.IsDirectory)
            {
                try
                {
                    using var child = PinnedFileSystem.OpenSubdirectory(directory, entry.Name);
                    total += MeasureDirectory(child, depth + 1, cancellation);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            else if (!entry.IsCloudOnly)
            {
                total += entry.Length;
            }
        }
        return total;
    }

    /// <summary>Bytes a file occupies on this disk: 0 for cloud placeholders and extra hard links.</summary>
    internal static long LocalSize(SafeFileHandle file, HandleInfo info)
    {
        if ((info.Attributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN)) != 0)
            return 0;
        var (length, _, links) = PinnedFileSystem.GetSize(file);
        return links > 1 ? 0 : length;
    }

    /// <summary>Deletes the entry <paramref name="name"/> of an open folder, with everything below it.</summary>
    public static void DeleteChild(SafeFileHandle parent, string name, TreeStats stats, CancellationToken cancellation = default)
    {
        SafeFileHandle child;
        try
        {
            child = PinnedFileSystem.OpenRelative(parent, name, DELETE | FILE_READ_ATTRIBUTES);
        }
        catch (FileSystemException e) when (e.IsNotFound) { return; }
        catch (FileSystemException e) when (e.IsInUse) { stats.InUse++; return; }
        catch (FileSystemException e) { stats.Fail(e); return; }
        using (child) DeleteOpened(child, stats, 0, cancellation);
    }

    /// <summary>Deletes an open item (opened with DELETE access) and everything below it.</summary>
    public static void DeleteOpened(SafeFileHandle item, TreeStats stats, int depth = 0, CancellationToken cancellation = default)
    {
        HandleInfo info;
        try { info = PinnedFileSystem.GetInfo(item); }
        catch (FileSystemException e) { stats.Fail(e); return; }

        long size = 0;
        if (info.IsDirectory && !info.IsReparsePoint)
        {
            if (depth > MaxDepth) { stats.Fail(new IOException("Folder too deep")); return; }
            SafeFileHandle list;
            try { list = PinnedFileSystem.ReOpen(item, PinnedFileSystem.DirectoryReadAccess); }
            catch (FileSystemException e) { stats.Fail(e); return; }
            using (list)
            {
                List<DirectoryEntry> entries;
                try { entries = PinnedFileSystem.Enumerate(list); }
                catch (FileSystemException e) { stats.Fail(e); return; }
                foreach (var entry in entries)
                {
                    cancellation.ThrowIfCancellationRequested();
                    SafeFileHandle child;
                    try
                    {
                        child = PinnedFileSystem.OpenRelative(list, entry.Name, DELETE | FILE_READ_ATTRIBUTES,
                            entry.IsDirectory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
                    }
                    catch (FileSystemException e) when (e.IsNotFound) { continue; }
                    catch (FileSystemException e) when (e.IsInUse) { stats.InUse++; continue; }
                    catch (FileSystemException e) { stats.Fail(e); continue; }
                    using (child) DeleteOpened(child, stats, depth + 1, cancellation);
                }
            }
        }
        else if (!info.IsReparsePoint)
        {
            try { size = LocalSize(item, info); } catch (FileSystemException) { }
        }

        try
        {
            PinnedFileSystem.Delete(item);
            stats.Bytes += size;
            stats.Removed++;
        }
        catch (FileSystemException e) when (e.Win32Error == ERROR_DIR_NOT_EMPTY)
        {
            // Something inside was in use or failed and is already counted.
        }
        catch (FileSystemException e) when (e.IsInUse || e.IsAccessDenied && !info.IsDirectory)
        {
            stats.InUse++;
        }
        catch (FileSystemException e)
        {
            stats.Fail(e);
        }
    }
}
