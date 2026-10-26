using System.Runtime.InteropServices;
using WinCleaner.Core;

namespace WinCleaner.Modules.Performance;

public sealed record SystemSnapshot(
    double CpuUsage,
    long MemoryTotal,
    long MemoryAvailable,
    long DiskTotal,
    long DiskFree,
    double? BatteryLevel,
    bool IsCharging,
    TimeSpan Uptime,
    int ProcessCount)
{
    public long MemoryUsed => MemoryTotal - MemoryAvailable;
    public double MemoryUsage => MemoryTotal > 0 ? (double)MemoryUsed / MemoryTotal : 0;
    public double DiskUsage => DiskTotal > 0 ? 1 - (double)DiskFree / DiskTotal : 0;
}

/// <summary>CPU, memory, system drive and battery, without administrator rights.</summary>
public sealed partial class SystemMonitor
{
    private ulong _idle, _kernel, _user;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint Length, MemoryLoad;
        public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag;
        public int BatteryLifeTime, BatteryFullLifeTime;
    }

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSystemTimes(out ulong idle, out ulong kernel, out ulong user);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX status);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

    /// <summary>CPU usage since the previous call of this instance (the first call returns 0).</summary>
    public SystemSnapshot Next()
    {
        double cpu = 0;
        if (GetSystemTimes(out ulong idle, out ulong kernel, out ulong user))
        {
            ulong total = (kernel - _kernel) + (user - _user);
            if (_kernel != 0 && total > 0) cpu = 1 - (double)(idle - _idle) / total;
            (_idle, _kernel, _user) = (idle, kernel, user);
        }
        return Snapshot() with { CpuUsage = Math.Clamp(cpu, 0, 1) };
    }

    public static SystemSnapshot Snapshot()
    {
        var memory = new MEMORYSTATUSEX { Length = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref memory);
        long diskTotal = 0, diskFree = 0;
        try
        {
            var drive = new DriveInfo(KnownPaths.SystemDrive);
            diskTotal = drive.TotalSize;
            diskFree = drive.AvailableFreeSpace;
        }
        catch (IOException) { }
        double? battery = null;
        bool charging = false;
        if (GetSystemPowerStatus(out var power) && power.BatteryFlag != 128 && power.BatteryLifePercent <= 100)
        {
            battery = power.BatteryLifePercent / 100.0;
            charging = power.ACLineStatus == 1;
        }
        var processes = System.Diagnostics.Process.GetProcesses();
        foreach (var p in processes) p.Dispose();
        return new SystemSnapshot(0, (long)memory.TotalPhys, (long)memory.AvailPhys, diskTotal, diskFree, battery, charging,
            TimeSpan.FromMilliseconds(Environment.TickCount64), processes.Length);
    }
}
