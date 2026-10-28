using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using Tramontana.Core;
using Tramontana.Modules.Apps;
using Tramontana.Modules.Performance;
using Tramontana.Modules.Privacy;

namespace Tramontana.Modules.Helper;

/// <summary>
/// What the elevated helper does for each request. Nothing is trusted from
/// the caller: every path is checked again against the system roots, the
/// shared-folder block list, TrustedInstaller ownership and Windows Resource
/// Protection; program folders must not belong to an installed or running
/// program; registry targets against the allow list; tasks, services and
/// Wi‑Fi names against what the helper itself finds on the system. Defender
/// and WMI are driven through WMI methods, never through a PowerShell string.
/// </summary>
public static class HelperService
{
    /// <summary>System folders the helper may remove items from.</summary>
    public static IReadOnlyList<string> SystemRoots() =>
        [.. Roots.System(), .. LeftoverFinder.SystemRoots()];

    /// <summary>First-level folders of the program and data roots that are never removed, nor anything inside them.</summary>
    private static readonly Dictionary<string, string[]> BlockedChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        [KnownPaths.ProgramFiles] = ["WindowsApps", "ModifiableWindowsApps", "Windows Defender", "Windows Defender Advanced Threat Protection",
            "Windows Mail", "Windows Media Player", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security",
            "Windows Sidebar", "WindowsPowerShell", "Common Files", "Internet Explorer", "Reference Assemblies", "Microsoft Update Health Tools",
            "Uninstall Information", "MSBuild", "dotnet", "PowerShell", "Tramontana", "WinCleaner"],
        [KnownPaths.ProgramFilesX86] = ["Windows Defender", "Windows Mail", "Windows Media Player", "Windows NT", "Windows Photo Viewer",
            "Windows Portable Devices", "Windows Sidebar", "WindowsPowerShell", "Common Files", "Internet Explorer", "Reference Assemblies",
            "Microsoft", "MSBuild", "dotnet", "Tramontana", "WinCleaner"],
        [KnownPaths.ProgramData] = ["Microsoft", "Package Cache", "Packages", "regid.1991-06.com.microsoft", "USOShared", "USOPrivate", "ssh",
            "WindowsHolographicDevices", "SoftwareDistribution", "Windows Defender", "Tramontana", "WinCleaner", "Application Data", "Desktop", "Documents",
            "Start Menu", "Templates", "Favorites"],
    };

    internal static bool IsBlocked(string path)
    {
        // The junk roots (C:\ProgramData\Microsoft\Windows\WER…) are precise: the block list is for the broad program roots.
        if (Roots.System().Any(r => PathGuard.IsStrictlyInside(path, r))) return false;
        foreach (var (root, children) in BlockedChildren)
        {
            if (!PathGuard.IsStrictlyInside(path, root)) continue;
            string first = PathGuard.RelativeComponents(path, root)[0];
            if (children.Contains(first, StringComparer.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>True for paths under the broad program roots (Program Files, ProgramData), where a whole program may live.</summary>
    private static bool IsInProgramRoots(string path) =>
        !Roots.System().Any(r => PathGuard.IsStrictlyInside(path, r))
        && (PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFiles) || PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFilesX86) || PathGuard.IsStrictlyInside(path, KnownPaths.ProgramData));

    /// <summary>
    /// Why a folder under the program roots must stay: it is (or contains) the
    /// install folder of a program that is still installed, or a program is
    /// running from it. The app only offers leftovers of removed programs, so a
    /// request that fails this test did not come from the app's screens.
    /// </summary>
    internal static string? ProgramFolderObjection(string path, IReadOnlyList<InstalledProgram> installed, bool checkRunning)
    {
        if (!IsInProgramRoots(path)) return null;
        foreach (var program in installed)
        {
            if (program.InstallLocation is { } location && PathGuard.IsValidPath(location) && PathGuard.IsSameOrInside(location, path))
                return $"cartella del programma installato «{program.Name}»";
        }
        if (checkRunning)
        {
            var running = InstalledPrograms.ProcessesIn(path);
            try { if (running.Count > 0) return "un programma è in esecuzione da questa cartella"; }
            finally { foreach (var p in running) p.Dispose(); }
        }
        return null;
    }

    private static IReadOnlyList<InstalledProgram> InstalledForCheck(IEnumerable<string> paths) =>
        paths.Any(IsInProgramRoots) ? InstalledPrograms.All(includeStore: false) : [];

    public static SafeRemover SystemRemover(RemovalMode mode) =>
        new(SystemRoots(), mode, OperationLog.Standard, SafeRemover.DefaultProtectedPaths(), Roots.SystemItems());

    public static async Task<HelperResponse> HandleAsync(HelperRequest request, CancellationToken cancellation)
    {
        try
        {
            var response = request.Operation switch
            {
                HelperOperation.Ping => new HelperResponse { Ok = true, Text = Environment.ProcessId.ToString() },
                HelperOperation.ScanSystemJunk => new HelperResponse { Ok = true, Report = ScanSystemJunk(cancellation) },
                HelperOperation.Remove => Remove(request, cancellation),
                HelperOperation.RemoveRegistry => RemoveRegistry(request),
                HelperOperation.Maintenance => await RunMaintenance(request, cancellation),
                HelperOperation.SetStartupApproved => SetStartupApproved(request),
                HelperOperation.SetTaskEnabled => TaskAction(request, delete: false),
                HelperOperation.DeleteTask => TaskAction(request, delete: true),
                HelperOperation.SetServiceStart => await SetServiceStart(request, cancellation),
                HelperOperation.DeleteWiFi => await DeleteWiFi(request, cancellation),
                HelperOperation.ReadPrefetch => new HelperResponse { Ok = true, Times = UserAssist.LastRunByExeName() },
                HelperOperation.CollectSystemEvidence => new HelperResponse { Ok = true, Text = await Protection.EvidenceCollection.CollectAsync(cancellation) },
                HelperOperation.Quarantine => QuarantineSystem(request),
                HelperOperation.RestoreQuarantined => RestoreQuarantined(request),
                HelperOperation.DeleteQuarantined => DeleteQuarantined(request),
                HelperOperation.TerminateProcess => TerminateProcess(request),
                HelperOperation.RemoveProtectionValue => RemoveProtectionValue(request),
                HelperOperation.RemoveDefenderExclusion => await RemoveDefenderExclusion(request, cancellation),
                HelperOperation.RemoveWmiSubscription => RemoveWmiSubscription(request),
                HelperOperation.EnableDefenderRealtime => await EnableDefenderRealtime(cancellation),
                HelperOperation.PinRules => new HelperResponse { Ok = true, Text = Protection.Rules.RulePins.Pin(new Protection.Rules.RuleStore()).ToString() },
                _ => new HelperResponse { Ok = false, Error = "Operazione sconosciuta" },
            };
            return response with { Id = request.Id };
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            OperationLog.Standard.Write($"helper\tERR {request.Operation}\t{e.Message}");
            return new HelperResponse { Id = request.Id, Ok = false, Error = e.Message };
        }
    }

    private static ScanReport ScanSystemJunk(CancellationToken cancellation)
    {
        var rules = SystemJunkModule.LoadRules();
        var adminRules = rules with { Rules = [.. rules.Rules.Where(r => r.Admin)] };
        var output = new RuleEngine().Evaluate(adminRules, cancellation);
        return new ScanReport("system-junk", output.Categories) { Notes = output.Notes, Unreadable = output.Unreadable };
    }

    private static HelperResponse Remove(HelperRequest request, CancellationToken cancellation)
    {
        var outcomes = new Dictionary<string, RemovalOutcome>(StringComparer.OrdinalIgnoreCase);
        var allowed = new List<string>();
        var installed = InstalledForCheck(request.Paths);
        foreach (var path in request.Paths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!PathGuard.IsValidPath(path)) outcomes[path] = new RemovalOutcome(path, 0, RemovalError.InvalidPath);
            else if (IsBlocked(path)) outcomes[path] = new RemovalOutcome(path, 0, RemovalError.SystemProtected, "Cartella di Windows o condivisa");
            else if (ProgramFolderObjection(path, installed, checkRunning: true) is { } objection) outcomes[path] = new RemovalOutcome(path, 0, RemovalError.SystemProtected, objection);
            else allowed.Add(path);
        }
        foreach (var outcome in SystemRemover(request.Mode).Remove(allowed, null, cancellation)) outcomes.TryAdd(outcome.Path, outcome);
        // Keep the request order for the caller.
        return new HelperResponse { Ok = true, Outcomes = [.. request.Paths.Select(p => outcomes.TryGetValue(p, out var o) ? o : new RemovalOutcome(p, 0, RemovalError.Failed))] };
    }

    private static HelperResponse RemoveRegistry(HelperRequest request)
    {
        var mode = request.Mode == RemovalMode.DryRun ? RemovalMode.DryRun : RemovalMode.Delete;
        var outcomes = new RegistryCleaner(mode, OperationLog.Standard).Remove(request.Registry);
        return new HelperResponse { Ok = true, Outcomes = [.. outcomes] };
    }

    private static async Task<HelperResponse> RunMaintenance(HelperRequest request, CancellationToken cancellation)
    {
        var task = request.Task switch
        {
            MaintenanceKind.FlushDns => MaintenanceTask.FlushDns,
            MaintenanceKind.FreeMemory => MaintenanceTask.FreeMemory,
            MaintenanceKind.WindowsCleanup => MaintenanceTask.WindowsCleanup,
            MaintenanceKind.ComponentCleanup => MaintenanceTask.ComponentCleanup,
            MaintenanceKind.SystemFileCheck => MaintenanceTask.SystemFileCheck,
            MaintenanceKind.RepairImage => MaintenanceTask.RepairImage,
            MaintenanceKind.DeliveryOptimization => MaintenanceTask.DeliveryOptimization,
            MaintenanceKind.OptimizeDrives => MaintenanceTask.OptimizeDrives,
            MaintenanceKind.RestorePoint => MaintenanceTask.RestorePoint,
            _ => throw new ArgumentException("Attività non ammessa"),
        };
        return new HelperResponse { Ok = true, Text = await Maintenance.RunAsync(task, cancellation) };
    }

    private static readonly string[] MachineApprovedKeys =
    [
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
    ];

    private static HelperResponse SetStartupApproved(HelperRequest request)
    {
        var key = request.Key is null ? null : RegistryCleaner.Normalize(request.Key);
        if (key is null || !MachineApprovedKeys.Contains(key, StringComparer.OrdinalIgnoreCase) || string.IsNullOrEmpty(request.Name))
            return new HelperResponse { Ok = false, Error = "Voce di avvio non ammessa" };
        // The entry must exist in the matching Run key or Startup folder.
        var exists = StartupManager.List(includeTasks: false, includeServices: false)
            .Any(i => string.Equals(i.ApprovedKey, key, StringComparison.OrdinalIgnoreCase) && string.Equals(i.ValueName, request.Name, StringComparison.OrdinalIgnoreCase));
        if (!exists) return new HelperResponse { Ok = false, Error = "Voce di avvio non trovata" };
        StartupManager.SetApproved(new StartupItem { Id = "", Name = request.Name, Kind = StartupKind.RunKey, Location = "", ApprovedKey = key, ValueName = request.Name }, request.Enabled);
        return new HelperResponse { Ok = true };
    }

    private static HelperResponse TaskAction(HelperRequest request, bool delete)
    {
        string? path = request.Name;
        var known = StartupManager.List(includeTasks: true, includeServices: false).Any(i => i.TaskPath == path);
        if (path is null || !known) return new HelperResponse { Ok = false, Error = "Attività non trovata" };
        if (delete) StartupManager.DeleteTask(path); else StartupManager.SetTaskEnabled(path, request.Enabled);
        return new HelperResponse { Ok = true };
    }

    private static async Task<HelperResponse> SetServiceStart(HelperRequest request, CancellationToken cancellation)
    {
        if (request.Number is not (2 or 3 or 4)) return new HelperResponse { Ok = false, Error = "Tipo di avvio non valido" };
        // Only services the startup list shows: not Microsoft's.
        var service = StartupManager.List(includeTasks: false, includeServices: true)
            .FirstOrDefault(i => i.Kind == StartupKind.Service && string.Equals(i.ServiceName, request.Name, StringComparison.OrdinalIgnoreCase));
        if (service?.ServiceName is not { } name) return new HelperResponse { Ok = false, Error = "Servizio non ammesso" };
        string start = request.Number switch { 2 => "auto", 3 => "demand", _ => "disabled" };
        var (exit, output) = await Maintenance.Exec("sc.exe", ["config", name, "start=", start], cancellation);
        OperationLog.Standard.Write($"service\t{start}\t{name}\t{exit}");
        return exit == 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = output.Trim() };
    }

    private static async Task<HelperResponse> DeleteWiFi(HelperRequest request, CancellationToken cancellation)
    {
        // Only the Wi‑Fi list is read (not the browsers: the helper never opens SQLite).
        var known = PrivacyScanner.WiFiProfiles().Any(i => i.Action is PrivacyAction.WiFi w && w.Profile == request.Name);
        if (request.Name is null || !known) return new HelperResponse { Ok = false, Error = "Rete non trovata" };
        var (exit, output) = await Maintenance.Exec("netsh.exe", ["wlan", "delete", "profile", $"name={request.Name}"], cancellation);
        OperationLog.Standard.Write($"wifi\tdelete\t{request.Name}\t{exit}");
        return exit == 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = output.Trim() };
    }

    // ---- Protection (M7) ----

    /// <summary>System files the quarantine may take: the system roots plus the program folders, never the blocked children.</summary>
    internal static IReadOnlyList<string> QuarantineRoots() =>
        [.. SystemRoots(), KnownPaths.ProgramFiles, KnownPaths.ProgramFilesX86, KnownPaths.ProgramData, Path.Combine(KnownPaths.SystemDrive, "Users", "Public"),
         Path.Combine(KnownPaths.Windows, "Tasks"), Path.Combine(KnownPaths.Windows, "System32", "Tasks")];

    /// <summary>The quarantine under ProgramData, owned by administrators and checked as such on every use (see SecureFolder).</summary>
    private static Protection.Quarantine SystemQuarantine()
    {
        SecureFolder.Ensure(DataFolders.SystemParent, "Tramontana");
        string folder = SecureFolder.Ensure(DataFolders.SystemParent, "Tramontana", "Quarantine");
        return new Protection.Quarantine(folder, OperationLog.Standard) { RequireAdminOwner = true };
    }

    private static HelperResponse QuarantineSystem(HelperRequest request)
    {
        var outcomes = new List<RemovalOutcome>();
        var quarantine = SystemQuarantine();
        var installed = InstalledForCheck(request.Paths);
        foreach (var path in request.Paths)
        {
            if (!PathGuard.IsValidPath(path)) { outcomes.Add(new RemovalOutcome(path, 0, RemovalError.InvalidPath)); continue; }
            if (IsBlocked(path) || PathGuard.IsStrictlyInside(path, Path.Combine(KnownPaths.Windows, "System32")) && !PathGuard.IsStrictlyInside(path, Path.Combine(KnownPaths.Windows, "System32", "Tasks")))
            { outcomes.Add(new RemovalOutcome(path, 0, RemovalError.SystemProtected, "Cartella di Windows o condivisa")); continue; }
            if (ProgramFolderObjection(path, installed, checkRunning: false) is { } objection)
            { outcomes.Add(new RemovalOutcome(path, 0, RemovalError.SystemProtected, objection)); continue; }
            try
            {
                var record = quarantine.Put(path, request.Name ?? Path.GetFileName(path), request.Key ?? "", QuarantineRoots(), isSystem: true);
                outcomes.Add(new RemovalOutcome(path, 0, null, record.Id.ToString("N") + "|" + record.StoredFolder + "|" + record.StoredName));
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException)
            { outcomes.Add(new RemovalOutcome(path, 0, RemovalError.Failed, e.Message)); }
        }
        return new HelperResponse { Ok = true, Outcomes = [.. outcomes] };
    }

    private static HelperResponse RestoreQuarantined(HelperRequest request)
    {
        var quarantine = SystemQuarantine();
        if (!Guid.TryParse(request.Name, out var id)) return new HelperResponse { Ok = false, Error = "Id non valido" };
        var record = quarantine.Records().FirstOrDefault(r => r.Id == id);
        if (record is null) return new HelperResponse { Ok = false, Error = "Elemento non trovato nella quarantena di sistema" };
        // Back only into the folders the quarantine took it from; never into Windows itself.
        quarantine.Restore(record, QuarantineRoots());
        return new HelperResponse { Ok = true };
    }

    private static HelperResponse DeleteQuarantined(HelperRequest request)
    {
        var quarantine = SystemQuarantine();
        if (!Guid.TryParse(request.Name, out var id)) return new HelperResponse { Ok = false, Error = "Id non valido" };
        var record = quarantine.Records().FirstOrDefault(r => r.Id == id);
        if (record is null) return new HelperResponse { Ok = false, Error = "Elemento non trovato nella quarantena di sistema" };
        quarantine.Delete(record);
        return new HelperResponse { Ok = true };
    }

    /// <summary>Critical processes are never killed, and the process must still run the image the app saw.</summary>
    private static readonly string[] NeverKill = ["csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "smss.exe", "svchost.exe", "dwm.exe", "explorer.exe", "MsMpEng.exe", "trhelper.exe", "Tramontana.exe"];

    private static HelperResponse TerminateProcess(HelperRequest request)
    {
        int pid = request.Number;
        string? expected = request.Key;
        if (pid <= 4 || expected is null) return new HelperResponse { Ok = false, Error = "Processo non valido" };
        string? actual = Protection.Processes.SystemProcesses.QueryPath(pid);
        if (actual is null || !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            return new HelperResponse { Ok = false, Error = "Il processo non è più quello indicato" };
        if (NeverKill.Contains(Path.GetFileName(actual), StringComparer.OrdinalIgnoreCase) && PathGuard.IsStrictlyInside(actual, KnownPaths.Windows))
            return new HelperResponse { Ok = false, Error = "Processo di sistema: non viene terminato" };
        // Nothing signed by Microsoft is killed from here: the app's own screen already refuses them.
        if (Signatures.Check(actual).IsMicrosoft && PathGuard.IsStrictlyInside(actual, KnownPaths.Windows))
            return new HelperResponse { Ok = false, Error = "Componente di Windows: non viene terminato" };
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
            OperationLog.Standard.Write($"helper\tkill\t{pid}\t{actual}");
            return new HelperResponse { Ok = true };
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or ArgumentException)
        { return new HelperResponse { Ok = false, Error = e.Message }; }
    }

    private static HelperResponse RemoveProtectionValue(HelperRequest request)
    {
        if (request.Key is null || request.Name is null) return new HelperResponse { Ok = false, Error = "Voce non valida" };
        try { return new HelperResponse { Ok = true, Text = Protection.ProtectionRegistry.Apply(request.Key, request.Name, OperationLog.Standard) }; }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException or IOException) { return new HelperResponse { Ok = false, Error = e.Message }; }
    }

    /// <summary>A value that may be passed to Defender or WMI: printable, no control characters, bounded.</summary>
    internal static bool IsPlainValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 1024 && value.All(c => c >= 0x20 && c != 0x7F);

    private const string DefenderScope = @"root\Microsoft\Windows\Defender";

    /// <summary>Calls a static method of MSFT_MpPreference (Remove, Set…) with one parameter: no shell, no quoting.</summary>
    internal static uint DefenderPreference(string method, string parameter, object value)
    {
        var scope = new ManagementScope(@"\\.\" + DefenderScope);
        scope.Connect();
        using var preferences = new ManagementClass(scope, new ManagementPath("MSFT_MpPreference"), null);
        using var parameters = preferences.GetMethodParameters(method);
        parameters[parameter] = value;
        using var result = preferences.InvokeMethod(method, parameters, null);
        return result is null ? 0u : Convert.ToUInt32(result["ReturnValue"] ?? 0u);
    }

    private static async Task<HelperResponse> RemoveDefenderExclusion(HelperRequest request, CancellationToken cancellation)
    {
        if (!IsPlainValue(request.Name)) return new HelperResponse { Ok = false, Error = "Esclusione non valida" };
        string name = request.Name!;
        string kind = request.Key switch { "Processo" => "ExclusionProcess", "Estensione" => "ExclusionExtension", _ => "ExclusionPath" };
        // The exclusion must exist: Defender's list, read by the helper itself, is the only source.
        var current = new Protection.SystemWmi().Query(DefenderScope, $"SELECT {kind} FROM MSFT_MpPreference").FirstOrDefault();
        var values = current?.GetValueOrDefault(kind) switch { string[] a => a, string s => [s], _ => [] };
        if (!values.Contains(name, StringComparer.OrdinalIgnoreCase)) return new HelperResponse { Ok = false, Error = "Esclusione non presente" };
        uint code;
        try { code = DefenderPreference("Remove", kind, new[] { name }); }
        catch (Exception e) when (e is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
            // Fallback: PowerShell with the value in an environment variable, never inside the command text.
            var (exit, output) = await Maintenance.Exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", $"Remove-MpPreference -{kind} $env:WC_VALUE"], cancellation,
                new Dictionary<string, string> { ["WC_VALUE"] = name });
            code = exit == 0 ? 0u : 1u;
            if (code != 0) OperationLog.Standard.Write($"helper\tdefender-exclusion fallback\t{e.Message}\t{output.Trim()}");
        }
        OperationLog.Standard.Write($"helper\tdefender-exclusion\t{kind}\t{name}\t{code}");
        return code == 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = $"Defender ha risposto {code}" };
    }

    /// <summary>Deletes the filter, the consumers and the bindings with that name through WMI objects, compared in code (no WQL built from the name).</summary>
    private static HelperResponse RemoveWmiSubscription(HelperRequest request)
    {
        if (!IsPlainValue(request.Name)) return new HelperResponse { Ok = false, Error = "Nome non valido" };
        string name = request.Name!;
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();
        int removed = 0;
        void DeleteWhere(string wql, Func<ManagementObject, bool> matches)
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
            foreach (ManagementObject o in searcher.Get())
            {
                using (o)
                {
                    if (!matches(o)) continue;
                    o.Delete();
                    removed++;
                }
            }
        }
        bool SameName(ManagementObject o) => string.Equals(o["Name"] as string, name, StringComparison.OrdinalIgnoreCase);
        DeleteWhere("SELECT * FROM __FilterToConsumerBinding", o =>
            string.Equals(Protection.EvidenceCollection.RefName(o["Filter"]), name, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Protection.EvidenceCollection.RefName(o["Consumer"]), name, StringComparison.OrdinalIgnoreCase));
        DeleteWhere("SELECT * FROM CommandLineEventConsumer", SameName);
        DeleteWhere("SELECT * FROM ActiveScriptEventConsumer", SameName);
        DeleteWhere("SELECT * FROM __EventFilter", SameName);
        OperationLog.Standard.Write($"helper\twmi-remove\t{name}\t{removed}");
        return removed > 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = "Sottoscrizione non trovata" };
    }

    private static async Task<HelperResponse> EnableDefenderRealtime(CancellationToken cancellation)
    {
        uint code;
        try { code = DefenderPreference("Set", "DisableRealtimeMonitoring", false); }
        catch (Exception e) when (e is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
            var (exit, output) = await Maintenance.Exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"], cancellation);
            code = exit == 0 ? 0u : 1u;
            if (code != 0) OperationLog.Standard.Write($"helper\tdefender-realtime fallback\t{e.Message}\t{output.Trim()}");
        }
        OperationLog.Standard.Write($"helper\tdefender-realtime\ton\t{code}");
        return code == 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = $"Defender ha risposto {code}" };
    }

    public static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
