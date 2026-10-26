using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Processes;

/// <summary>One running process.</summary>
public sealed record ProcessRecord(int Pid, int ParentPid, string Name, string? Path, string? CommandLine, DateTime? Started, bool IsMine);

/// <summary>Raw counters of a process at one instant.</summary>
public sealed record ProcessCounters(TimeSpan Cpu, long PrivateBytes, long IoRead, long IoWritten, int Threads);

/// <summary>What a process did between two samples.</summary>
public sealed record ProcessActivity(ProcessRecord Process, double Cpu, long Memory, double DiskBytesPerSecond, int Threads);

/// <summary>Lists processes and reads their counters. Injected so tests can feed fixed samples.</summary>
public interface IProcessSource
{
    IReadOnlyList<ProcessRecord> List();
    ProcessCounters? Counters(int pid);
}

/// <summary>The real processes: names, parents and command lines from WMI (one query), the rest from the process handle.</summary>
public sealed partial class SystemProcesses(IWmiSource? wmi = null) : IProcessSource
{
    private readonly IWmiSource _wmi = wmi ?? new SystemWmi();
    public const string Query = "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process";

    public IReadOnlyList<ProcessRecord> List()
    {
        var list = new List<ProcessRecord>();
        foreach (var row in _wmi.Query(@"root\cimv2", Query))
        {
            int pid = Convert.ToInt32(row.GetValueOrDefault("ProcessId") ?? 0);
            if (pid <= 0) continue;
            string name = row.GetValueOrDefault("Name") as string ?? "?";
            string? path = row.GetValueOrDefault("ExecutablePath") as string;
            if (path is null)
            {
                try { path = QueryPath(pid); } catch (Exception) { }
            }
            list.Add(new ProcessRecord(pid, Convert.ToInt32(row.GetValueOrDefault("ParentProcessId") ?? 0), name, path,
                row.GetValueOrDefault("CommandLine") as string, Checks.DefenderCheck.ToDate(row.GetValueOrDefault("CreationDate")), IsOwnedByCurrentUser(pid)));
        }
        return list;
    }

    public ProcessCounters? Counters(int pid)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid) return null;
        if (!GetProcessTimes(handle, out _, out _, out long kernel, out long user)) return null;
        var memory = new PROCESS_MEMORY_COUNTERS_EX { cb = (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS_EX>() };
        GetProcessMemoryInfo(handle, ref memory, memory.cb);
        GetProcessIoCounters(handle, out var io);
        int threads = 0;
        try { using var p = Process.GetProcessById(pid); threads = p.Threads.Count; } catch (Exception) { }
        return new ProcessCounters(TimeSpan.FromTicks(kernel + user), (long)memory.PrivateUsage, (long)io.ReadTransferCount, (long)io.WriteTransferCount, threads);
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MEMORY_COUNTERS_EX
    {
        public uint cb, PageFaultCount;
        public UIntPtr PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivateUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessMemoryInfo(SafeProcessHandle process, ref PROCESS_MEMORY_COUNTERS_EX counters, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessIoCounters(SafeProcessHandle process, out IO_COUNTERS counters);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    public static string? QueryPath(int pid)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid) return null;
        var buffer = new char[32_768];
        uint size = (uint)buffer.Length;
        return QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    /// <summary>True when the process runs under the current user's account.</summary>
    public static bool IsOwnedByCurrentUser(int pid)
    {
        try
        {
            using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (handle.IsInvalid) return false;
            if (!OpenProcessToken(handle, TokenQuery, out var token)) return false;
            using (token)
            using (var identity = new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle()))
            using (var me = System.Security.Principal.WindowsIdentity.GetCurrent())
                return identity.User is not null && me.User is not null && identity.User.Equals(me.User);
        }
        catch (Exception) { return false; }
    }
}

/// <summary>Fixed processes and counters for tests.</summary>
public sealed class FakeProcesses : IProcessSource
{
    public List<ProcessRecord> Records { get; } = [];
    public Dictionary<int, ProcessCounters> CounterTable { get; } = [];
    public IReadOnlyList<ProcessRecord> List() => Records;
    public ProcessCounters? Counters(int pid) => CounterTable.GetValueOrDefault(pid);
}

/// <summary>Samples every process; CPU and disk are rates between two calls. Keep one instance per screen.</summary>
public sealed class ProcessSampler(IProcessSource? source = null)
{
    private readonly IProcessSource _source = source ?? new SystemProcesses();
    private Dictionary<int, (ProcessCounters Counters, DateTime Time)> _previous = [];
    private readonly Lock _lock = new();

    public IReadOnlyList<ProcessActivity> Sample(DateTime? at = null)
    {
        var now = at ?? DateTime.UtcNow;
        lock (_lock)
        {
            var next = new Dictionary<int, (ProcessCounters, DateTime)>();
            var activities = new List<ProcessActivity>();
            foreach (var record in _source.List())
            {
                var counters = _source.Counters(record.Pid);
                if (counters is null) continue;
                next[record.Pid] = (counters, now);
                if (!_previous.TryGetValue(record.Pid, out var last)) continue;
                double seconds = Math.Max((now - last.Time).TotalSeconds, 0.001);
                double cpu = Math.Max(0, (counters.Cpu - last.Counters.Cpu).TotalSeconds) / seconds;
                double disk = Math.Max(0, (counters.IoRead + counters.IoWritten) - (last.Counters.IoRead + last.Counters.IoWritten)) / seconds;
                activities.Add(new ProcessActivity(record, cpu, counters.PrivateBytes, disk, counters.Threads));
            }
            _previous = next;
            return activities;
        }
    }
}
