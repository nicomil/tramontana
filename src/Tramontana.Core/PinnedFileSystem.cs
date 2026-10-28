using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using static Tramontana.Core.Native.NativeMethods;

namespace Tramontana.Core;

/// <summary>An I/O error with the Win32 code it maps to.</summary>
public sealed class FileSystemException : IOException
{
    public int Win32Error { get; }

    public FileSystemException(int win32Error, string? name)
        : base($"{new Win32Exception(win32Error).Message}{(name is null ? "" : $" ({name})")}")
    {
        Win32Error = win32Error;
        HResult = unchecked((int)0x8007_0000 | win32Error);
    }

    public bool IsNotFound => Win32Error is ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND;
    public bool IsInUse => Win32Error is ERROR_SHARING_VIOLATION or ERROR_CANT_ACCESS_FILE or 33 /* lock violation */;
    public bool IsAccessDenied => Win32Error == ERROR_ACCESS_DENIED;
    public bool IsExisting => Win32Error is ERROR_ALREADY_EXISTS or ERROR_FILE_EXISTS;
}

/// <summary>One entry of a folder, read from a folder handle.</summary>
public readonly record struct DirectoryEntry(
    string Name, uint Attributes, long Length, long AllocationSize, long LastWriteTimeUtc, UInt128 FileId = default)
{
    public bool IsDirectory => (Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    public bool IsReparsePoint => (Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

    /// <summary>Cloud files (OneDrive placeholders) that are not stored on this disk.</summary>
    public bool IsCloudOnly => (Attributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN)) != 0;

    public DateTime LastWriteUtc => DateTime.FromFileTimeUtc(LastWriteTimeUtc);
}

/// <summary>Attributes and reparse tag of an open handle.</summary>
public readonly record struct HandleInfo(uint Attributes, uint ReparseTag)
{
    public bool IsDirectory => (Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    public bool IsReparsePoint => (Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

/// <summary>
/// File operations that work on handles instead of paths. A folder is opened
/// once and everything below it is opened relative to that handle, one name at
/// a time, never following junctions or symbolic links. Swapping a folder for
/// a link while an operation runs therefore makes it fail instead of sending
/// it somewhere else.
/// </summary>
public static unsafe partial class PinnedFileSystem
{
    public const uint DirectoryReadAccess = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

    /// <summary>
    /// Opens a folder by its full path. Only used for the allowed roots and
    /// volume roots; with <paramref name="followReparsePoints"/> false the
    /// folder itself must be a real folder, not a junction or a link.
    /// </summary>
    public static SafeFileHandle OpenDirectoryPath(string path, uint access = DirectoryReadAccess, bool followReparsePoints = true)
    {
        var handle = CreateFile(path, access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | (followReparsePoints ? 0 : FILE_FLAG_OPEN_REPARSE_POINT), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new FileSystemException(error, path);
        }
        var info = GetInfo(handle);
        if (!info.IsDirectory)
        {
            handle.Dispose();
            throw new FileSystemException(267 /* ERROR_DIRECTORY */, path);
        }
        if (!followReparsePoints && info.IsReparsePoint)
        {
            handle.Dispose();
            throw new ReparsePointException(path);
        }
        return handle;
    }

    /// <summary>
    /// Opens one entry of an open folder. The name must be a single component:
    /// separators, "." and ".." are refused. Reparse points are opened as
    /// themselves, never followed.
    /// </summary>
    public static SafeFileHandle OpenRelative(SafeFileHandle parent, string name, uint access,
        uint options = 0, uint share = FILE_SHARE_ALL, uint disposition = FILE_OPEN)
    {
        if (!PathGuard.IsValidName(name)) throw new ArgumentException($"Invalid name: {name}", nameof(name));

        fixed (char* chars = name)
        {
            var unicode = new UNICODE_STRING
            {
                Length = (ushort)(name.Length * 2),
                MaximumLength = (ushort)(name.Length * 2),
                Buffer = chars,
            };
            bool added = false;
            parent.DangerousAddRef(ref added);
            try
            {
                var attributes = new OBJECT_ATTRIBUTES
                {
                    Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = &unicode,
                    Attributes = OBJ_CASE_INSENSITIVE,
                };
                int status = NtCreateFile(out IntPtr raw, access | SYNCHRONIZE, &attributes, out _, IntPtr.Zero, 0,
                    share, disposition, options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                    IntPtr.Zero, 0);
                if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), name);
                return new SafeFileHandle(raw, ownsHandle: true);
            }
            finally
            {
                if (added) parent.DangerousRelease();
            }
        }
    }

    /// <summary>Opens a sub-folder for listing, refusing reparse points.</summary>
    public static SafeFileHandle OpenSubdirectory(SafeFileHandle parent, string name, uint access = DirectoryReadAccess)
    {
        var handle = OpenRelative(parent, name, access, FILE_DIRECTORY_FILE);
        if (GetInfo(handle).IsReparsePoint)
        {
            handle.Dispose();
            throw new ReparsePointException(name);
        }
        return handle;
    }

    /// <summary>Opens the folder at <paramref name="components"/> below <paramref name="root"/>, one name at a time.</summary>
    public static SafeFileHandle OpenPath(SafeFileHandle root, IReadOnlyList<string> components, uint access = DirectoryReadAccess)
    {
        SafeFileHandle current = root;
        bool ownsCurrent = false;
        try
        {
            for (int i = 0; i < components.Count; i++)
            {
                var next = OpenSubdirectory(current, components[i], i == components.Count - 1 ? access : DirectoryReadAccess);
                if (ownsCurrent) current.Dispose();
                current = next;
                ownsCurrent = true;
            }
            if (!ownsCurrent)
            {
                // No components: hand back a new handle to the root itself.
                return ReOpen(root, access);
            }
            ownsCurrent = false;
            return current;
        }
        finally
        {
            if (ownsCurrent) current.Dispose();
        }
    }

    /// <summary>
    /// Like <see cref="OpenPath"/>, but creates the folders that do not exist
    /// yet (one name at a time, never through a reparse point). Used to put a
    /// quarantined item back when its folder was removed in the meantime.
    /// </summary>
    public static SafeFileHandle OpenPathCreating(SafeFileHandle root, IReadOnlyList<string> components, uint access = DirectoryReadAccess)
    {
        SafeFileHandle current = root;
        bool ownsCurrent = false;
        try
        {
            for (int i = 0; i < components.Count; i++)
            {
                var next = OpenRelative(current, components[i], i == components.Count - 1 ? access : DirectoryReadAccess, FILE_DIRECTORY_FILE, disposition: FILE_OPEN_IF);
                if (GetInfo(next).IsReparsePoint)
                {
                    next.Dispose();
                    throw new ReparsePointException(components[i]);
                }
                if (ownsCurrent) current.Dispose();
                current = next;
                ownsCurrent = true;
            }
            if (!ownsCurrent) return ReOpen(root, access);
            ownsCurrent = false;
            return current;
        }
        finally
        {
            if (ownsCurrent) current.Dispose();
        }
    }

    /// <summary>
    /// Opens an alternate data stream of an open file (<c>:Zone.Identifier</c>)
    /// relative to the file's handle, so the file is never named by path.
    /// </summary>
    public static SafeFileHandle OpenStream(SafeFileHandle file, string streamName, uint access, uint disposition)
    {
        if (string.IsNullOrEmpty(streamName) || streamName.Contains('\\') || streamName.Contains(':')) throw new ArgumentException($"Invalid stream name: {streamName}", nameof(streamName));
        string name = ":" + streamName;
        fixed (char* chars = name)
        {
            var unicode = new UNICODE_STRING { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = chars };
            bool added = false;
            file.DangerousAddRef(ref added);
            try
            {
                var attributes = new OBJECT_ATTRIBUTES
                {
                    Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                    RootDirectory = file.DangerousGetHandle(),
                    ObjectName = &unicode,
                    Attributes = OBJ_CASE_INSENSITIVE,
                };
                int status = NtCreateFile(out IntPtr raw, access | SYNCHRONIZE, &attributes, out _, IntPtr.Zero, 0,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, disposition, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, IntPtr.Zero, 0);
                if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), name);
                return new SafeFileHandle(raw, ownsHandle: true);
            }
            finally
            {
                if (added) file.DangerousRelease();
            }
        }
    }

    /// <summary>Sets the attributes of an open item (FILE_WRITE_ATTRIBUTES access); zero means "normal".</summary>
    public static void SetAttributes(SafeFileHandle handle, uint attributes)
    {
        FILE_BASIC_INFO info = default;
        info.FileAttributes = attributes == 0 ? FILE_ATTRIBUTE_NORMAL : attributes;
        int status = NtSetInformationFile(handle, out _, &info, (uint)sizeof(FILE_BASIC_INFO), FileBasicInformation);
        if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), null);
    }

    /// <summary>
    /// Replaces the DACL of an open item (WRITE_DAC access) with the one in
    /// <paramref name="security"/>, through the handle: a junction swapped in
    /// under the path cannot send the new permissions elsewhere.
    /// </summary>
    public static void SetDacl(SafeFileHandle handle, System.Security.AccessControl.FileSystemSecurity security)
    {
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        uint information = DACL_SECURITY_INFORMATION | (security.AreAccessRulesProtected ? PROTECTED_DACL_SECURITY_INFORMATION : 0);
        if (!SetKernelObjectSecurity(handle, information, descriptor))
            throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
    }

    /// <summary>
    /// A second handle to the same object, with other access rights: an NT
    /// open relative to the handle with an empty name, so no path is involved.
    /// </summary>
    public static SafeFileHandle ReOpen(SafeFileHandle handle, uint access)
    {
        var unicode = new UNICODE_STRING();
        bool added = false;
        handle.DangerousAddRef(ref added);
        try
        {
            var attributes = new OBJECT_ATTRIBUTES
            {
                Length = (uint)sizeof(OBJECT_ATTRIBUTES),
                RootDirectory = handle.DangerousGetHandle(),
                ObjectName = &unicode,
                Attributes = OBJ_CASE_INSENSITIVE,
            };
            int status = NtCreateFile(out IntPtr raw, access | SYNCHRONIZE, &attributes, out _, IntPtr.Zero, 0,
                FILE_SHARE_ALL, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, IntPtr.Zero, 0);
            if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), null);
            return new SafeFileHandle(raw, ownsHandle: true);
        }
        finally
        {
            if (added) handle.DangerousRelease();
        }
    }

    public static HandleInfo GetInfo(SafeFileHandle handle)
    {
        FILE_ATTRIBUTE_TAG_INFO info;
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, (uint)sizeof(FILE_ATTRIBUTE_TAG_INFO)))
            throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
        return new HandleInfo(info.FileAttributes, info.ReparseTag);
    }

    public static (long Length, long Allocation, uint Links) GetSize(SafeFileHandle handle)
    {
        FILE_STANDARD_INFO info;
        if (!GetFileInformationByHandleEx(handle, FileStandardInfo, &info, (uint)sizeof(FILE_STANDARD_INFO)))
            throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
        return (info.EndOfFile, info.AllocationSize, info.NumberOfLinks);
    }

    public static DateTime GetLastWriteUtc(SafeFileHandle handle)
    {
        FILE_BASIC_INFO info;
        if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &info, (uint)sizeof(FILE_BASIC_INFO)))
            throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
        return DateTime.FromFileTimeUtc(info.LastWriteTime);
    }

    /// <summary>Volume serial number and 128-bit file id: identifies a file across renames.</summary>
    public static (ulong Volume, UInt128 Id) GetFileId(SafeFileHandle handle)
    {
        FILE_ID_INFO info;
        if (!GetFileInformationByHandleEx(handle, FileIdInfo, &info, (uint)sizeof(FILE_ID_INFO)))
            throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
        return (info.VolumeSerialNumber, new UInt128(info.FileIdHigh, info.FileIdLow));
    }

    /// <summary>Full path of an open handle, without the \\?\ prefix.</summary>
    public static string GetFinalPath(SafeFileHandle handle)
    {
        Span<char> buffer = stackalloc char[1024];
        fixed (char* p = buffer)
        {
            uint length = GetFinalPathNameByHandle(handle, p, (uint)buffer.Length, 0);
            if (length == 0) throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
            string path;
            if (length >= buffer.Length)
            {
                var big = new char[length + 1];
                fixed (char* q = big)
                {
                    length = GetFinalPathNameByHandle(handle, q, (uint)big.Length, 0);
                    if (length == 0) throw new FileSystemException(Marshal.GetLastPInvokeError(), null);
                    path = new string(q, 0, (int)length);
                }
            }
            else
            {
                path = new string(p, 0, (int)length);
            }
            if (path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + path[8..];
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path[4..];
            return path;
        }
    }

    /// <summary>Lists a folder opened with list access. "." and ".." are skipped.</summary>
    public static List<DirectoryEntry> Enumerate(SafeFileHandle directory) => Enumerate(directory, withIds: false);

    /// <summary>
    /// Lists a folder, optionally with the 128-bit file id of each entry
    /// (NTFS and ReFS), which identifies hard links of the same file without
    /// opening it. Falls back to entries without ids on other file systems.
    /// </summary>
    public static List<DirectoryEntry> Enumerate(SafeFileHandle directory, bool withIds)
    {
        var entries = new List<DirectoryEntry>();
        const int size = 64 * 1024;
        byte* buffer = (byte*)NativeMemory.Alloc(size);
        try
        {
            int restartClass = withIds ? FileIdExtdDirectoryRestartInfo : FileFullDirectoryRestartInfo;
            int nextClass = withIds ? FileIdExtdDirectoryInfo : FileFullDirectoryInfo;
            int infoClass = restartClass;
            while (true)
            {
                if (!GetFileInformationByHandleEx(directory, infoClass, buffer, size))
                {
                    int error = Marshal.GetLastPInvokeError();
                    if (error == ERROR_NO_MORE_FILES) break;
                    if (withIds && infoClass == restartClass && error is ERROR_INVALID_PARAMETER or ERROR_NOT_SUPPORTED)
                        return Enumerate(directory, withIds: false);
                    throw new FileSystemException(error, null);
                }
                infoClass = nextClass;
                int offset = 0;
                while (true)
                {
                    var span = new ReadOnlySpan<byte>(buffer + offset, size - offset);
                    uint next = BinaryPrimitives.ReadUInt32LittleEndian(span);
                    long lastWrite = BinaryPrimitives.ReadInt64LittleEndian(span[24..]);
                    long length = BinaryPrimitives.ReadInt64LittleEndian(span[40..]);
                    long allocation = BinaryPrimitives.ReadInt64LittleEndian(span[48..]);
                    uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(span[56..]);
                    int nameBytes = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[60..]);
                    UInt128 id = default;
                    int nameOffset = 68;
                    if (withIds)
                    {
                        // FILE_ID_EXTD_DIR_INFO: ..., EaSize, ReparsePointTag, FileId (16 bytes), FileName.
                        ulong low = BinaryPrimitives.ReadUInt64LittleEndian(span[72..]);
                        ulong high = BinaryPrimitives.ReadUInt64LittleEndian(span[80..]);
                        id = new UInt128(high, low);
                        nameOffset = 88;
                    }
                    string name = new((char*)(buffer + offset + nameOffset), 0, nameBytes / 2);
                    if (name is not ("." or ".."))
                        entries.Add(new DirectoryEntry(name, attributes, length, allocation, lastWrite, id));
                    if (next == 0) break;
                    offset += (int)next;
                }
            }
        }
        finally
        {
            NativeMemory.Free(buffer);
        }
        return entries;
    }

    /// <summary>
    /// Marks an open handle for deletion with POSIX semantics: the name goes
    /// away at once, even if another program still has the file open. Folders
    /// must be empty. Read-only files are deleted too.
    /// </summary>
    public static void Delete(SafeFileHandle handle)
    {
        uint flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                     FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        int status = NtSetInformationFile(handle, out _, &flags, sizeof(uint), FileDispositionInformationEx);
        if (status >= 0) return;

        int error = (int)RtlNtStatusToDosError(status);
        if (error is not (ERROR_INVALID_PARAMETER or ERROR_NOT_SUPPORTED or 1 /* invalid function */))
            throw new FileSystemException(error, null);

        // File systems without POSIX deletes (FAT, exFAT).
        byte delete = 1;
        status = NtSetInformationFile(handle, out _, &delete, 1, FileDispositionInformation);
        if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), null);
    }

    /// <summary>
    /// Moves an open file or folder into another open folder of the same
    /// volume under a new name. An existing item with that name is never
    /// replaced.
    /// </summary>
    public static void Rename(SafeFileHandle item, SafeFileHandle targetDirectory, string newName)
    {
        if (!PathGuard.IsValidName(newName)) throw new ArgumentException($"Invalid name: {newName}", nameof(newName));

        // FILE_RENAME_INFORMATION_EX: Flags, padding, RootDirectory, FileNameLength, FileName.
        int nameBytes = newName.Length * 2;
        int headerSize = IntPtr.Size == 8 ? 20 : 12;
        int total = headerSize + nameBytes + 2;
        byte* buffer = (byte*)NativeMemory.AllocZeroed((nuint)total);
        bool added = false;
        targetDirectory.DangerousAddRef(ref added);
        try
        {
            *(uint*)buffer = 0; // never replace
            *(IntPtr*)(buffer + IntPtr.Size) = targetDirectory.DangerousGetHandle();
            *(uint*)(buffer + IntPtr.Size * 2) = (uint)nameBytes;
            fixed (char* chars = newName)
                Buffer.MemoryCopy(chars, buffer + headerSize, nameBytes, nameBytes);
            int status = NtSetInformationFile(item, out _, buffer, (uint)total, FileRenameInformationEx);
            if (status < 0) throw new FileSystemException((int)RtlNtStatusToDosError(status), newName);
        }
        finally
        {
            if (added) targetDirectory.DangerousRelease();
            NativeMemory.Free(buffer);
        }
    }

    /// <summary>True when the file or folder is owned by TrustedInstaller (Windows components).</summary>
    public static bool IsOwnedByTrustedInstaller(SafeFileHandle handle)
    {
        uint result = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, out IntPtr owner,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IntPtr descriptor);
        if (result != 0) throw new FileSystemException((int)result, null);
        try
        {
            var sid = new System.Security.Principal.SecurityIdentifier(owner);
            return sid.Value == KnownSids.TrustedInstaller;
        }
        finally
        {
            LocalFree(descriptor);
        }
    }
}

/// <summary>A junction, symbolic link or mount point was found where a real folder was expected.</summary>
public sealed class ReparsePointException(string name) : IOException($"Reparse point in the path: {name}");

public static class KnownSids
{
    public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    public const string LocalSystem = "S-1-5-18";
    public const string Administrators = "S-1-5-32-544";
}
