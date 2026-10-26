using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using static WinCleaner.Core.Native.NativeMethods;

namespace WinCleaner.Core;

/// <summary>An item in a Recycle Bin, read from its <c>$I</c> file.</summary>
public sealed record RecycledItem(
    char Drive,
    string InfoName,
    string DataName,
    string OriginalPath,
    long Size,
    DateTime DeletedUtc)
{
    public string DataPath => $@"{Drive}:\$Recycle.Bin\{RecycleBin.CurrentUserSid}\{DataName}";
}

/// <summary>
/// The current user's Recycle Bin on each volume (<c>X:\$Recycle.Bin\&lt;SID&gt;</c>).
///
/// Items are moved in by renaming their handle into the bin folder, never by
/// path, and an existing name is never replaced. Next to each moved item
/// (<c>$R……</c>) goes a <c>$I……</c> file in the version 2 format Explorer
/// writes (version, size, deletion time, original path), so the item shows up
/// in the Recycle Bin and "Restore" puts it back where it was.
/// </summary>
public static partial class RecycleBin
{
    public static string CurrentUserSid { get; } = WindowsIdentity.GetCurrent().User?.Value
        ?? throw new InvalidOperationException("No user SID");

    private const uint BinAccess = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
                                   FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE;

    /// <summary>Opens the user's bin folder on a drive, or returns null if the drive has none yet.</summary>
    public static SafeFileHandle? TryOpen(char drive)
    {
        try
        {
            using var volume = PinnedFileSystem.OpenDirectoryPath($@"{char.ToUpperInvariant(drive)}:\");
            return PinnedFileSystem.OpenPath(volume, ["$Recycle.Bin", CurrentUserSid], BinAccess);
        }
        catch (FileSystemException e) when (e.IsNotFound)
        {
            return null;
        }
    }

    /// <summary>
    /// Opens the bin folder, letting Explorer create it first when the user
    /// never deleted anything on that drive (a placeholder file is recycled
    /// with the shell and then removed again).
    /// </summary>
    public static SafeFileHandle? OpenOrCreate(char drive)
    {
        var handle = TryOpen(drive);
        if (handle is not null) return handle;
        if (!TryBootstrap(drive)) return null;
        return TryOpen(drive);
    }

    /// <summary>Moves an open item into the bin. The handle needs DELETE access.</summary>
    public static RecycledItem Move(SafeFileHandle bin, char drive, SafeFileHandle item, string originalPath, long size)
    {
        string extension = Path.GetExtension(originalPath);
        if (!PathGuard.IsValidName("x" + extension)) extension = "";
        for (int attempt = 0; attempt < 32; attempt++)
        {
            string id = RandomId();
            string infoName = "$I" + id + extension;
            string dataName = "$R" + id + extension;
            SafeFileHandle info;
            try
            {
                info = PinnedFileSystem.OpenRelative(bin, infoName, FILE_WRITE_DATA | DELETE,
                    FILE_NON_DIRECTORY_FILE, share: 0, disposition: FILE_CREATE);
            }
            catch (FileSystemException e) when (e.IsExisting)
            {
                continue;
            }

            using (info)
            {
                var deleted = DateTime.UtcNow;
                RandomAccess.Write(info, InfoRecord(originalPath, size, deleted), 0);
                try
                {
                    PinnedFileSystem.Rename(item, bin, dataName);
                }
                catch (Exception e)
                {
                    try { PinnedFileSystem.Delete(info); } catch { /* best effort */ }
                    if (e is FileSystemException { IsExisting: true }) continue;
                    throw;
                }
                _ = SHUpdateRecycleBinIcon();
                return new RecycledItem(drive, infoName, dataName, originalPath, size, deleted);
            }
        }
        throw new IOException("Could not pick a free name in the Recycle Bin");
    }

    /// <summary>The <c>$I</c> record, version 2: Int64 version, Int64 size, FILETIME, Int32 length, path + NUL.</summary>
    public static byte[] InfoRecord(string originalPath, long size, DateTime deletedUtc)
    {
        var record = new byte[28 + (originalPath.Length + 1) * 2];
        BinaryPrimitives.WriteInt64LittleEndian(record, 2);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(8), size);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(16), deletedUtc.ToFileTimeUtc());
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(24), originalPath.Length + 1);
        Encoding.Unicode.GetBytes(originalPath, record.AsSpan(28));
        return record;
    }

    /// <summary>Parses a <c>$I</c> record (versions 1 and 2).</summary>
    public static (string Path, long Size, DateTime DeletedUtc)? ParseInfo(ReadOnlySpan<byte> data)
    {
        if (data.Length < 24) return null;
        long version = BinaryPrimitives.ReadInt64LittleEndian(data);
        long size = BinaryPrimitives.ReadInt64LittleEndian(data[8..]);
        long time = BinaryPrimitives.ReadInt64LittleEndian(data[16..]);
        string path;
        if (version == 2)
        {
            if (data.Length < 28) return null;
            int chars = BinaryPrimitives.ReadInt32LittleEndian(data[24..]);
            if (chars <= 0 || 28 + chars * 2 > data.Length) return null;
            path = Encoding.Unicode.GetString(data.Slice(28, chars * 2)).TrimEnd('\0');
        }
        else if (version == 1)
        {
            // Windows Vista to 8.1: fixed 520-byte path.
            if (data.Length < 24 + 520) return null;
            path = Encoding.Unicode.GetString(data.Slice(24, 520)).Split('\0')[0];
        }
        else
        {
            return null;
        }
        DateTime deleted;
        try { deleted = DateTime.FromFileTimeUtc(time); } catch (ArgumentOutOfRangeException) { deleted = DateTime.MinValue; }
        return (path, size, deleted);
    }

    /// <summary>Lists the items in the user's bin on a drive.</summary>
    public static List<RecycledItem> List(char drive)
    {
        var items = new List<RecycledItem>();
        using var bin = TryOpen(drive);
        if (bin is null) return items;
        var entries = PinnedFileSystem.Enumerate(bin);
        var names = new HashSet<string>(entries.Select(e => e.Name), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (!entry.Name.StartsWith("$I", StringComparison.OrdinalIgnoreCase) || entry.IsDirectory) continue;
            string dataName = "$R" + entry.Name[2..];
            if (!names.Contains(dataName)) continue;
            try
            {
                using var info = PinnedFileSystem.OpenRelative(bin, entry.Name, FILE_READ_DATA, FILE_NON_DIRECTORY_FILE);
                var buffer = new byte[Math.Min(entry.Length, 70_000)];
                int read = RandomAccess.Read(info, buffer, 0);
                if (ParseInfo(buffer.AsSpan(0, read)) is { } parsed)
                    items.Add(new RecycledItem(char.ToUpperInvariant(drive), entry.Name, dataName, parsed.Path, parsed.Size, parsed.DeletedUtc));
            }
            catch (IOException)
            {
                // Unreadable record: leave it to Explorer.
            }
        }
        return items;
    }

    /// <summary>Permanently deletes one item and its record from the bin.</summary>
    public static TreeStats Purge(RecycledItem item, CancellationToken cancellation = default)
    {
        using var bin = TryOpen(item.Drive) ?? throw new FileSystemException(ERROR_PATH_NOT_FOUND, "$Recycle.Bin");
        var stats = new TreeStats();
        HandleTree.DeleteChild(bin, item.DataName, stats, cancellation);
        if (stats.InUse == 0 && stats.Failed == 0)
        {
            try
            {
                using var info = PinnedFileSystem.OpenRelative(bin, item.InfoName, DELETE | FILE_READ_ATTRIBUTES, FILE_NON_DIRECTORY_FILE);
                PinnedFileSystem.Delete(info);
            }
            catch (FileSystemException e) when (e.IsNotFound) { }
        }
        _ = SHUpdateRecycleBinIcon();
        return stats;
    }

    /// <summary>Fixed local drives that may hold a Recycle Bin.</summary>
    public static IEnumerable<char> FixedDrives() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => char.ToUpperInvariant(d.Name[0]));

    private static string RandomId()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Span<char> chars = stackalloc char[6];
        for (int i = 0; i < chars.Length; i++) chars[i] = alphabet[Random.Shared.Next(alphabet.Length)];
        return new string(chars);
    }

    private static bool TryBootstrap(char drive)
    {
        string temp = KnownPaths.Temp;
        if (char.ToUpperInvariant(temp[0]) != char.ToUpperInvariant(drive)) return false;
        string placeholder = Path.Combine(temp, $"wincleaner-bin-{Guid.NewGuid():N}.tmp");
        File.WriteAllBytes(placeholder, []);
        if (!ShellRecycle(placeholder))
        {
            File.Delete(placeholder);
            return false;
        }
        foreach (var item in List(drive).Where(i => string.Equals(i.OriginalPath, placeholder, StringComparison.OrdinalIgnoreCase)))
            Purge(item);
        return true;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCTW
    {
        public IntPtr hwnd;
        public uint wFunc;
        public IntPtr pFrom;
        public IntPtr pTo;
        public ushort fFlags;
        public int fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public IntPtr lpszProgressTitle;
    }

    [LibraryImport("shell32.dll", EntryPoint = "SHFileOperationW")]
    private static partial int SHFileOperation(ref SHFILEOPSTRUCTW op);

    private static bool ShellRecycle(string path)
    {
        IntPtr from = Marshal.StringToHGlobalUni(path + "\0");
        try
        {
            var op = new SHFILEOPSTRUCTW
            {
                wFunc = 3, // FO_DELETE
                pFrom = from,
                fFlags = 0x40 | 0x10 | 0x4 | 0x400, // ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
            };
            return SHFileOperation(ref op) == 0 && op.fAnyOperationsAborted == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(from);
        }
    }
}
