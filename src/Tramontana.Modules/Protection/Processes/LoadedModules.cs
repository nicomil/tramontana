using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Tramontana.Core;

namespace Tramontana.Modules.Protection.Processes;

/// <summary>The DLLs a process has loaded (own processes without privileges, every process from the helper's evidence).</summary>
public static partial class LoadedModules
{
    private const uint ProcessQueryInformation = 0x0400, ProcessVmRead = 0x0010, ListModulesAll = 0x03;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EnumProcessModulesEx(SafeProcessHandle process, [Out] IntPtr[] modules, uint size, out uint needed, uint filter);

    [LibraryImport("psapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetModuleFileNameExW(SafeProcessHandle process, IntPtr module, [Out] char[] name, uint size);

    public static List<string> Of(int pid)
    {
        var result = new List<string>();
        using var handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
        if (handle.IsInvalid) return result;
        var modules = new IntPtr[2048];
        if (!EnumProcessModulesEx(handle, modules, (uint)(modules.Length * IntPtr.Size), out uint needed, ListModulesAll)) return result;
        int count = Math.Min((int)(needed / IntPtr.Size), modules.Length);
        var buffer = new char[32_768];
        for (int i = 0; i < count; i++)
        {
            uint length = GetModuleFileNameExW(handle, modules[i], buffer, (uint)buffer.Length);
            if (length > 0) result.Add(new string(buffer, 0, (int)length));
        }
        return result;
    }

    /// <summary>Modules outside the Windows and program folders: the only ones worth a signature check.</summary>
    public static bool IsOutsidePrograms(string path) =>
        !Suspicion.IsInWindows(path) && !PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFiles) && !PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFilesX86)
        && !path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
}
