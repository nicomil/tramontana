using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinCleaner.Core.Native;

/// <summary>
/// The Win32 and NT functions the file system code needs. Everything that
/// touches files on behalf of a removal goes through handles opened relative
/// to their parent folder (the Windows equivalent of openat), so a folder
/// swapped for a junction during a clean cannot redirect it elsewhere.
/// </summary>
internal static unsafe partial class NativeMethods
{
    // Access rights
    public const uint DELETE = 0x0001_0000;
    public const uint READ_CONTROL = 0x0002_0000;
    public const uint WRITE_DAC = 0x0004_0000;
    public const uint SYNCHRONIZE = 0x0010_0000;
    public const uint FILE_LIST_DIRECTORY = 0x0001;
    public const uint FILE_READ_DATA = 0x0001;
    public const uint FILE_WRITE_DATA = 0x0002;
    public const uint FILE_ADD_FILE = 0x0002;
    public const uint FILE_ADD_SUBDIRECTORY = 0x0004;
    public const uint FILE_TRAVERSE = 0x0020;
    public const uint FILE_READ_ATTRIBUTES = 0x0080;
    public const uint FILE_WRITE_ATTRIBUTES = 0x0100;

    // Share modes
    public const uint FILE_SHARE_READ = 0x1;
    public const uint FILE_SHARE_WRITE = 0x2;
    public const uint FILE_SHARE_DELETE = 0x4;
    public const uint FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // NtCreateFile dispositions and options
    public const uint FILE_OPEN = 1;
    public const uint FILE_CREATE = 2;
    public const uint FILE_OPEN_IF = 3;
    public const uint FILE_OVERWRITE_IF = 5;
    public const uint FILE_DIRECTORY_FILE = 0x0000_0001;
    public const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
    public const uint FILE_NON_DIRECTORY_FILE = 0x0000_0040;
    public const uint FILE_OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
    public const uint FILE_OPEN_REPARSE_POINT = 0x0020_0000;

    public const uint OBJ_CASE_INSENSITIVE = 0x0000_0040;
    /// <summary>Fails the open if any reparse point is met while parsing the name (Windows 10 1607+).</summary>
    public const uint OBJ_DONT_REPARSE = 0x0000_1000;

    // CreateFileW
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x0200_0000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x0020_0000;

    // File attributes
    public const uint FILE_ATTRIBUTE_READONLY = 0x1;
    public const uint FILE_ATTRIBUTE_HIDDEN = 0x2;
    public const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
    public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    public const uint FILE_ATTRIBUTE_OFFLINE = 0x1000;
    public const uint FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x0004_0000;
    public const uint FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x0040_0000;

    // NT information classes
    public const int FileBasicInformation = 4;
    public const int FileRenameInformationEx = 65;
    public const int FileDispositionInformation = 13;
    public const int FileDispositionInformationEx = 64;

    public const uint FILE_DISPOSITION_FLAG_DELETE = 0x1;
    public const uint FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x2;
    public const uint FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x10;
    public const uint FILE_RENAME_FLAG_POSIX_SEMANTICS = 0x2;

    // Win32 information classes (GetFileInformationByHandleEx)
    public const int FileBasicInfo = 0;
    public const int FileStandardInfo = 1;
    public const int FileAttributeTagInfo = 9;
    public const int FileFullDirectoryInfo = 14;
    public const int FileFullDirectoryRestartInfo = 15;
    public const int FileIdInfo = 18;
    public const int FileIdExtdDirectoryInfo = 19;
    public const int FileIdExtdDirectoryRestartInfo = 20;

    public const int ERROR_FILE_NOT_FOUND = 2;
    public const int ERROR_PATH_NOT_FOUND = 3;
    public const int ERROR_ACCESS_DENIED = 5;
    public const int ERROR_SHARING_VIOLATION = 32;
    public const int ERROR_NO_MORE_FILES = 18;
    public const int ERROR_DIR_NOT_EMPTY = 145;
    public const int ERROR_ALREADY_EXISTS = 183;
    public const int ERROR_FILE_EXISTS = 80;
    public const int ERROR_NOT_SAME_DEVICE = 17;
    public const int ERROR_INVALID_PARAMETER = 87;
    public const int ERROR_NOT_SUPPORTED = 50;
    public const int ERROR_CANT_ACCESS_FILE = 1920;

    public const uint SE_FILE_OBJECT = 1;
    public const uint OWNER_SECURITY_INFORMATION = 0x1;
    public const uint DACL_SECURITY_INFORMATION = 0x4;
    public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x8000_0000;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public UNICODE_STRING* ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ATTRIBUTE_TAG_INFO
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_STANDARD_INFO
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending;
        public byte Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_BASIC_INFO
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ID_INFO
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [LibraryImport("ntdll.dll")]
    public static partial int NtCreateFile(out IntPtr fileHandle, uint desiredAccess, OBJECT_ATTRIBUTES* objectAttributes,
        out IO_STATUS_BLOCK ioStatusBlock, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

    [LibraryImport("ntdll.dll")]
    public static partial int NtSetInformationFile(SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock,
        void* fileInformation, uint length, int fileInformationClass);

    [LibraryImport("ntdll.dll")]
    public static partial uint RtlNtStatusToDosError(int status);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, void* info, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    public static partial uint GetFinalPathNameByHandle(SafeFileHandle file, char* path, uint length, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WriteFile(SafeFileHandle file, byte* buffer, uint toWrite, out uint written, IntPtr overlapped);

    [LibraryImport("advapi32.dll")]
    public static partial uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint securityInfo,
        out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr securityDescriptor);

    [LibraryImport("kernel32.dll")]
    public static partial IntPtr LocalFree(IntPtr mem);

    /// <summary>Sets the security of an open handle (files included): the DACL goes to the object itself, never through a path.</summary>
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetKernelObjectSecurity(SafeFileHandle handle, uint securityInformation, byte[] securityDescriptor);

    [LibraryImport("sfc.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SfcIsFileProtected(IntPtr rpcHandle, string fileName);

    [LibraryImport("shell32.dll")]
    public static partial int SHUpdateRecycleBinIcon();
}
