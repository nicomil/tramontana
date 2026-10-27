using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using WinCleaner.Core;

namespace WinCleaner.Modules.Performance;

public enum MaintenanceTask
{
    FlushDns,
    FreeMemory,
    RebuildIconCache,
    RestartExplorer,
    WindowsCleanup,
    ComponentCleanup,
    SystemFileCheck,
    RepairImage,
    DeliveryOptimization,
    OptimizeDrives,
    RestorePoint,
    WipeFreeSpace,
}

public sealed record MaintenanceInfo(MaintenanceTask Task, string Title, string Description, bool NeedsAdmin, bool IsLong, string? Confirm = null);

/// <summary>
/// Maintenance tasks. Each one maps to a fixed command or API call with no
/// arguments from outside: the elevated helper accepts only this enum.
/// </summary>
public static partial class Maintenance
{
    public static readonly IReadOnlyList<MaintenanceInfo> All =
    [
        new(MaintenanceTask.FlushDns, "Svuota la cache DNS", "Utile se un sito non si apre dopo un cambio di indirizzo.", true, false),
        new(MaintenanceTask.FreeMemory, "Libera memoria", "Riduce la memoria usata dai programmi aperti e svuota la memoria in standby.", true, false),
        new(MaintenanceTask.RebuildIconCache, "Ricostruisci icone e miniature", "Risolve icone sbagliate o vuote. Esplora risorse si riavvia.", false, false,
            "Esplora risorse verrà chiuso e riaperto: le finestre delle cartelle si chiudono."),
        new(MaintenanceTask.RestartExplorer, "Riavvia Esplora risorse", "Sblocca barra delle applicazioni e menu Start bloccati.", false, false,
            "Le finestre delle cartelle aperte si chiudono."),
        new(MaintenanceTask.WindowsCleanup, "Pulizia di Windows", "Usa i gestori di Pulizia disco: vecchie installazioni (Windows.old), file degli aggiornamenti, driver superati, log di installazione.", true, true,
            "Dopo aver tolto Windows.old non si può più tornare alla versione precedente di Windows."),
        new(MaintenanceTask.ComponentCleanup, "Pulizia dei componenti", "Toglie le versioni superate dei componenti di Windows (DISM). Gli aggiornamenti già installati non si potranno più disinstallare.", true, true,
            "Gli aggiornamenti installati finora non si potranno più disinstallare."),
        new(MaintenanceTask.SystemFileCheck, "Controlla i file di sistema", "Verifica e ripara i file di Windows (sfc /scannow).", true, true),
        new(MaintenanceTask.RepairImage, "Ripara l'immagine di Windows", "Scarica da Windows Update i componenti danneggiati (DISM /RestoreHealth).", true, true),
        new(MaintenanceTask.DeliveryOptimization, "Svuota la cache di Ottimizzazione recapito", "File degli aggiornamenti condivisi con altri PC.", true, false),
        new(MaintenanceTask.OptimizeDrives, "Ottimizza le unità", "TRIM per gli SSD, deframmentazione per i dischi tradizionali.", true, true),
        new(MaintenanceTask.RestorePoint, "Crea un punto di ripristino", "Permette di tornare allo stato attuale di Windows se qualcosa va storto.", true, false),
        new(MaintenanceTask.WipeFreeSpace, "Cancella lo spazio libero", "Sovrascrive lo spazio libero di C: perché i file già eliminati non si possano recuperare. Richiede molto tempo.", false, true,
            "Può richiedere ore e rallenta il PC finché non finisce."),
    ];

    public static MaintenanceInfo Info(MaintenanceTask task) => All.First(i => i.Task == task);

    /// <summary>Disk Cleanup handlers run by "Pulizia di Windows" (Windows ESD files stay: "Reimposta il PC" needs them).</summary>
    public static readonly string[] CleanupHandlers =
    [
        "Previous Installations", "Update Cleanup", "Windows Upgrade Log Files", "Temporary Setup Files",
        "Delivery Optimization Files", "Device Driver Packages", "Setup Log Files", "Downloaded Program Files",
        "Windows Error Reporting Files", "System error memory dump files", "System error minidump files",
    ];

    /// <summary>Size of Windows.old, shown next to "Pulizia di Windows".</summary>
    public static long PreviousWindowsSize()
    {
        var old = Path.Combine(KnownPaths.SystemDrive, "Windows.old");
        return Directory.Exists(old) ? FileWalker.Measure(old).Bytes : 0;
    }

    /// <summary>Runs a task with the rights of this process. Returns a short result for the user.</summary>
    public static async Task<string> RunAsync(MaintenanceTask task, CancellationToken cancellation)
    {
        OperationLog.Standard.Write($"maintenance\tstart\t{task}");
        string result = task switch
        {
            MaintenanceTask.FlushDns => await Exec("ipconfig.exe", ["/flushdns"], cancellation) is (0, _) ? "Cache DNS svuotata" : "Non riuscito",
            MaintenanceTask.FreeMemory => FreeMemory(),
            MaintenanceTask.RebuildIconCache => await RebuildIconCache(cancellation),
            MaintenanceTask.RestartExplorer => await RestartExplorer(cancellation),
            MaintenanceTask.WindowsCleanup => await WindowsCleanup(cancellation),
            MaintenanceTask.ComponentCleanup => Result(await Exec("dism.exe", ["/Online", "/Cleanup-Image", "/StartComponentCleanup"], cancellation)),
            MaintenanceTask.SystemFileCheck => Result(await Exec("sfc.exe", ["/scannow"], cancellation)),
            MaintenanceTask.RepairImage => Result(await Exec("dism.exe", ["/Online", "/Cleanup-Image", "/RestoreHealth"], cancellation)),
            MaintenanceTask.DeliveryOptimization => Result(await Exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Delete-DeliveryOptimizationCache -Force"], cancellation)),
            MaintenanceTask.OptimizeDrives => Result(await Exec("defrag.exe", ["/C", "/O", "/H"], cancellation)),
            MaintenanceTask.RestorePoint => RestorePoint(),
            MaintenanceTask.WipeFreeSpace => Result(await Exec("cipher.exe", [$"/w:{KnownPaths.SystemDrive}"], cancellation)),
            _ => "Sconosciuto",
        };
        OperationLog.Standard.Write($"maintenance\tend\t{task}\t{result}");
        return result;
    }

    private static string Result((int Exit, string Output) r) => r.Exit == 0 ? "Completato" : $"Terminato con codice {r.Exit}";

    /// <summary>System Restore through WMI (root\default SystemRestore), no PowerShell involved.</summary>
    private static string RestorePoint()
    {
        try
        {
            var scope = new System.Management.ManagementScope(@"\\.\root\default");
            scope.Connect();
            using var restore = new System.Management.ManagementClass(scope, new System.Management.ManagementPath("SystemRestore"), null);
            try { restore.InvokeMethod("Enable", [KnownPaths.SystemDrive]); } catch (System.Management.ManagementException) { }
            // RESTORE_POINT_TYPE MODIFY_SETTINGS = 12, EVENT_TYPE BEGIN_SYSTEM_CHANGE = 100.
            var result = restore.InvokeMethod("CreateRestorePoint", ["WinCleaner", 12u, 100u]);
            uint code = Convert.ToUInt32(result ?? 1u);
            return code == 0 ? "Completato" : $"Terminato con codice {code}";
        }
        catch (Exception e) when (e is System.Management.ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
            return "Non riuscito: " + e.Message;
        }
    }

    /// <summary>Runs a Windows tool with a clean environment; <paramref name="environment"/> adds variables (the safe way to pass a value to PowerShell: $env:NAME).</summary>
    internal static async Task<(int Exit, string Output)> Exec(string file, string[] args, CancellationToken cancellation, IReadOnlyDictionary<string, string>? environment = null)
    {
        string path = Path.IsPathRooted(file) ? file : Path.Combine(Environment.SystemDirectory, file);
        if (file == "powershell.exe") path = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var info = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) info.ArgumentList.Add(a);
        // No runtime hooks and no user module path reach the tool (see ProcessEnvironment).
        ProcessEnvironment.Sanitize(info);
        if (environment is not null) foreach (var (key, value) in environment) info.Environment[key] = value;
        using var p = Process.Start(info)!;
        var output = p.StandardOutput.ReadToEndAsync(cancellation);
        var error = p.StandardError.ReadToEndAsync(cancellation);
        try { await p.WaitForExitAsync(cancellation); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch (Exception) { } throw; }
        return (p.ExitCode, await output + await error);
    }

    /// <summary>Trims the working sets of every process we may open, then (as administrator) purges the standby list.</summary>
    public static string FreeMemory()
    {
        long before = SystemMonitor.Snapshot().MemoryAvailable;
        foreach (var p in Process.GetProcesses())
        {
            try { EmptyWorkingSet(p.Handle); } catch (Exception) { }
            p.Dispose();
        }
        bool purged = PurgeStandbyList();
        long after = SystemMonitor.Snapshot().MemoryAvailable;
        long freed = Math.Max(0, after - before);
        return $"{Format.Bytes(freed)} liberati{(purged ? "" : " (memoria in standby: serve l'amministratore)")}";
    }

    [LibraryImport("psapi.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EmptyWorkingSet(IntPtr process);

    [LibraryImport("ntdll.dll")]
    private static partial int NtSetSystemInformation(int infoClass, ref int info, int length);

    /// <summary>SystemMemoryListInformation (80) with MemoryPurgeStandbyList (4); needs SeProfileSingleProcessPrivilege.</summary>
    private static bool PurgeStandbyList()
    {
        if (!Privileges.Enable("SeProfileSingleProcessPrivilege")) return false;
        int command = 4;
        return NtSetSystemInformation(80, ref command, sizeof(int)) >= 0;
    }

    private static async Task<string> RestartExplorer(CancellationToken cancellation)
    {
        foreach (var p in Process.GetProcessesByName("explorer")) { try { p.Kill(); } catch { } p.Dispose(); }
        await Task.Delay(1500, cancellation);
        if (Process.GetProcessesByName("explorer").Length == 0)
            Process.Start(new ProcessStartInfo(Path.Combine(KnownPaths.Windows, "explorer.exe")) { UseShellExecute = true });
        return "Esplora risorse riavviato";
    }

    private static async Task<string> RebuildIconCache(CancellationToken cancellation)
    {
        foreach (var p in Process.GetProcessesByName("explorer")) { try { p.Kill(); } catch { } p.Dispose(); }
        await Task.Delay(1500, cancellation);
        var folder = Path.Combine(KnownPaths.LocalAppData, "Microsoft", "Windows", "Explorer");
        var files = Directory.Exists(folder)
            ? Directory.GetFiles(folder).Where(f => Path.GetFileName(f).StartsWith("iconcache_", StringComparison.OrdinalIgnoreCase)
                                               || Path.GetFileName(f).StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase)).ToList()
            : [];
        var legacy = Path.Combine(KnownPaths.LocalAppData, "IconCache.db");
        if (File.Exists(legacy)) files.Add(legacy);
        var outcomes = new SafeRemover([folder, KnownPaths.LocalAppData], RemovalMode.Delete, OperationLog.Standard).Remove(files);
        Process.Start(new ProcessStartInfo(Path.Combine(KnownPaths.Windows, "explorer.exe")) { UseShellExecute = true });
        return $"{outcomes.Count(o => o.Succeeded)} file di cache ricreati";
    }

    private static async Task<string> WindowsCleanup(CancellationToken cancellation)
    {
        const string flag = "StateFlags0777";
        using var caches = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches", writable: true)
            ?? throw new UnauthorizedAccessException("Serve l'amministratore");
        var set = new List<string>();
        try
        {
            foreach (var name in CleanupHandlers)
            {
                using var handler = caches.OpenSubKey(name, writable: true);
                if (handler is null) continue;
                handler.SetValue(flag, 2, RegistryValueKind.DWord);
                set.Add(name);
            }
            var r = await Exec("cleanmgr.exe", ["/sagerun:777"], cancellation);
            return r.Exit == 0 ? "Pulizia di Windows completata" : $"Terminato con codice {r.Exit}";
        }
        finally
        {
            foreach (var name in set)
            {
                using var handler = caches.OpenSubKey(name, writable: true);
                handler?.DeleteValue(flag, throwOnMissingValue: false);
            }
        }
    }
}

/// <summary>Enables a privilege the process token holds (administrators have most of them disabled).</summary>
public static partial class Privileges
{
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public uint Count; public long Luid; public uint Attributes; }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValue(string? system, string name, out long luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TOKEN_PRIVILEGES state, int length, IntPtr previous, IntPtr returnLength);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    public static bool Enable(string name)
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out var token)) return false;
        try
        {
            if (!LookupPrivilegeValue(null, name, out long luid)) return false;
            var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = 0x2 };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastPInvokeError() == 0;
        }
        finally { CloseHandle(token); }
    }
}
