using System.IO.Enumeration;
using WinCleaner.Core;

namespace WinCleaner.Modules;

/// <summary>Broad kind of a file, used to group big files.</summary>
public enum FileKind { Video, Audio, Image, Archive, DiskImage, Document, Other }

public static class FileKinds
{
    private static readonly Dictionary<string, FileKind> ByExtension = Build();

    private static Dictionary<string, FileKind> Build()
    {
        var map = new Dictionary<string, FileKind>(StringComparer.OrdinalIgnoreCase);
        void Add(FileKind kind, string list) { foreach (var e in list.Split(' ')) map["." + e] = kind; }
        Add(FileKind.Video, "mp4 mkv avi mov wmv m4v webm flv mpg mpeg ts m2ts mts 3gp vob");
        Add(FileKind.Audio, "mp3 wav flac aac m4a ogg wma opus aiff aif alac");
        Add(FileKind.Image, "jpg jpeg png gif bmp tif tiff heic heif webp avif raw cr2 cr3 nef arw dng orf rw2 psd ico jxl");
        Add(FileKind.Archive, "zip rar 7z tar gz tgz bz2 xz zst cab lz lzma");
        Add(FileKind.DiskImage, "iso img vhd vhdx vmdk qcow2 exe msi msix msixbundle appx appxbundle");
        Add(FileKind.Document, "pdf doc docx xls xlsx ppt pptx odt ods odp txt rtf csv md epub pages key numbers");
        return map;
    }

    public static FileKind Of(string path) =>
        ByExtension.TryGetValue(Path.GetExtension(path), out var kind) ? kind : FileKind.Other;

    public static string Title(this FileKind kind) => kind switch
    {
        FileKind.Video => "Video",
        FileKind.Audio => "Audio",
        FileKind.Image => "Immagini",
        FileKind.Archive => "Archivi",
        FileKind.DiskImage => "Immagini disco e installer",
        FileKind.Document => "Documenti",
        _ => "Altri file",
    };
}

/// <summary>A file found in the user's folders.</summary>
public readonly record struct FileRecord(string Path, long Size, DateTime LastWriteUtc, DateTime LastAccessUtc, FileAttributes Attributes)
{
    /// <summary>Last time the file was written or (when Windows records it) read.</summary>
    public DateTime LastUsedUtc => LastAccessUtc > LastWriteUtc ? LastAccessUtc : LastWriteUtc;
}

/// <summary>
/// Walks the user's own folders (Desktop, Documents, Downloads, Pictures…).
/// Skips links, hidden system folders, version-control and package folders,
/// and cloud files that are not on this PC: reading them would download them.
/// </summary>
public static class UserFilesWalker
{
    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".svn", ".hg", "node_modules", "$RECYCLE.BIN", "System Volume Information", ".venv", "__pycache__",
    };

    public static IEnumerable<FileRecord> Walk(IEnumerable<string> roots, long minimumSize, CancellationToken cancellation = default)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            if (!Directory.Exists(root) || !seen.Add(root)) continue;
            var enumerable = new FileSystemEnumerable<FileRecord>(root,
                (ref FileSystemEntry e) => new FileRecord(e.ToFullPath(), e.Length, e.LastWriteTimeUtc.UtcDateTime,
                    e.LastAccessTimeUtc.UtcDateTime, e.Attributes),
                FileWalker.Options(recurse: true))
            {
                ShouldIncludePredicate = (ref FileSystemEntry e) =>
                    !e.IsDirectory && e.Length >= minimumSize && FileWalker.IsLocalOnly(e.Attributes)
                    && (e.Attributes & FileAttributes.ReparsePoint) == 0,
                ShouldRecursePredicate = (ref FileSystemEntry e) =>
                    (e.Attributes & FileAttributes.ReparsePoint) == 0
                    && (e.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != (FileAttributes.Hidden | FileAttributes.System)
                    && !SkippedFolders.Contains(e.FileName.ToString()),
            };
            foreach (var record in enumerable)
            {
                cancellation.ThrowIfCancellationRequested();
                yield return record;
            }
        }
    }

    /// <summary>"3 mesi fa", "2 anni fa"…</summary>
    public static string Age(DateTime utc)
    {
        var days = (DateTime.UtcNow - utc).TotalDays;
        if (days < 1) return "oggi";
        if (days < 2) return "ieri";
        if (days < 30) return $"{(int)days} giorni fa";
        if (days < 365) return (int)(days / 30) is var m && m == 1 ? "un mese fa" : $"{(int)(days / 30)} mesi fa";
        int years = (int)(days / 365);
        return years == 1 ? "un anno fa" : $"{years} anni fa";
    }
}
