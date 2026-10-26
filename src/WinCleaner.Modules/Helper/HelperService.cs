using System.Diagnostics;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Apps;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Privacy;

namespace WinCleaner.Modules.Helper;

/// <summary>
/// What the elevated helper does for each request. Nothing is trusted from
/// the caller: every path is checked again against the system roots, the
/// shared-folder block list, TrustedInstaller ownership and Windows Resource
/// Protection; registry targets against the allow list; tasks, services and
/// Wi‑Fi names against what the helper itself finds on the system.
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
            "Uninstall Information", "MSBuild", "dotnet", "PowerShell", "WinCleaner"],
        [KnownPaths.ProgramFilesX86] = ["Windows Defender", "Windows Mail", "Windows Media Player", "Windows NT", "Windows Photo Viewer",
            "Windows Portable Devices", "Windows Sidebar", "WindowsPowerShell", "Common Files", "Internet Explorer", "Reference Assemblies",
            "Microsoft", "MSBuild", "dotnet", "WinCleaner"],
        [KnownPaths.ProgramData] = ["Microsoft", "Package Cache", "Packages", "regid.1991-06.com.microsoft", "USOShared", "USOPrivate", "ssh",
            "WindowsHolographicDevices", "SoftwareDistribution", "Windows Defender", "WinCleaner", "Application Data", "Desktop", "Documents",
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
        var outcomes = new List<RemovalOutcome>();
        var allowed = new List<string>();
        foreach (var path in request.Paths)
        {
            if (IsBlocked(path)) outcomes.Add(new RemovalOutcome(path, 0, RemovalError.SystemProtected, "Cartella di Windows o condivisa"));
            else allowed.Add(path);
        }
        outcomes.AddRange(SystemRemover(request.Mode).Remove(allowed, null, cancellation));
        // Keep the request order for the caller.
        var byPath = outcomes.ToDictionary(o => o.Path, StringComparer.OrdinalIgnoreCase);
        return new HelperResponse { Ok = true, Outcomes = [.. request.Paths.Select(p => byPath[p])] };
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
        // Only services the startup list shows: not Microsoft's and not in the Windows folder.
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
        var known = PrivacyScanner.Scan().Any(i => i.Action is PrivacyAction.WiFi w && w.Profile == request.Name);
        if (request.Name is null || !known) return new HelperResponse { Ok = false, Error = "Rete non trovata" };
        var (exit, output) = await Maintenance.Exec("netsh.exe", ["wlan", "delete", "profile", $"name={request.Name}"], cancellation);
        OperationLog.Standard.Write($"wifi\tdelete\t{request.Name}\t{exit}");
        return exit == 0 ? new HelperResponse { Ok = true } : new HelperResponse { Ok = false, Error = output.Trim() };
    }

    public static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
