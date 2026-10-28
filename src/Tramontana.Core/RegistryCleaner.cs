using System.Diagnostics;
using Microsoft.Win32;

namespace Tramontana.Core;

/// <summary>A registry key or value to delete.</summary>
public sealed record RegistryTarget(string KeyPath, string? ValueName = null)
{
    public bool IsValue => ValueName is not null;
    public override string ToString() => IsValue ? $@"{KeyPath} [{(ValueName!.Length == 0 ? "(predefinito)" : ValueName)}]" : KeyPath;
}

/// <summary>
/// Deletes registry keys and values, only in the places a cleaner may touch,
/// after exporting each one to a .reg file that restores it with a double click.
///
/// Allowed: per-program keys under HKCU\Software and HKLM\SOFTWARE (not
/// Microsoft, Classes, Policies and the other shared roots), plus a closed
/// list of Windows places that only hold per-program entries (Uninstall,
/// App Paths, Run, SharedDLLs, MuiCache, the Explorer history lists). Never
/// HKLM\SYSTEM, SAM, SECURITY, HARDWARE or other users' hives.
/// </summary>
public sealed class RegistryCleaner
{
    private readonly OperationLog? _log;
    public string BackupFolder { get; }
    public RemovalMode Mode { get; }

    public RegistryCleaner(RemovalMode mode, OperationLog? log = null, string? backupFolder = null)
    {
        Mode = mode;
        _log = log;
        BackupFolder = backupFolder ?? Path.Combine(DataFolders.Backups, "registro-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
    }

    // Subtrees where only the entries inside may be deleted (not the key itself).
    private static readonly string[] WindowsLists =
    [
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs",
        @"HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps",
    ];

    // Vendor roots under Software that hold shared or system settings.
    private static readonly HashSet<string> SharedVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Classes", "Policies", "Clients", "RegisteredApplications", "WOW6432Node", "Wow6432Node",
        "Windows", "ODBC", "Intel", "Khronos", "Partner", "DefaultUserEnvironment", "OEM",
    };

    /// <summary>Full form of a key path (HKCU → HKEY_CURRENT_USER), or null when the hive is not allowed.</summary>
    public static string? Normalize(string keyPath)
    {
        var path = keyPath.Trim().TrimEnd('\\');
        int slash = path.IndexOf('\\');
        string hive = slash < 0 ? path : path[..slash];
        string rest = slash < 0 ? "" : path[(slash + 1)..];
        string? full = hive.ToUpperInvariant() switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => "HKEY_CURRENT_USER",
            "HKLM" or "HKEY_LOCAL_MACHINE" => "HKEY_LOCAL_MACHINE",
            _ => null,
        };
        if (full is null || rest.Split('\\').Any(c => c.Length == 0)) return null;
        return rest.Length == 0 ? full : full + @"\" + rest;
    }

    /// <summary>True when the key (or a value inside it) may be deleted.</summary>
    public static bool IsAllowed(RegistryTarget target)
    {
        var key = Normalize(target.KeyPath);
        if (key is null) return false;
        foreach (var list in WindowsLists)
        {
            if (target.IsValue && string.Equals(key, list, StringComparison.OrdinalIgnoreCase)) return true;
            if (PathGuard.IsStrictlyInside(key, list)) return true;
        }
        var parts = key.Split('\\');
        // HKEY_CURRENT_USER\Software\Vendor[\...] or HKEY_LOCAL_MACHINE\SOFTWARE[\WOW6432Node]\Vendor[\...]
        if (parts.Length < 3 || !parts[1].Equals("Software", StringComparison.OrdinalIgnoreCase)) return false;
        int vendor = 2;
        if (parts[0] == "HKEY_LOCAL_MACHINE" && parts[2].Equals("WOW6432Node", StringComparison.OrdinalIgnoreCase)) vendor = 3;
        if (parts.Length <= vendor) return false;
        return !SharedVendors.Contains(parts[vendor]);
    }

    /// <summary>Exports, then deletes. Needs administrator rights for HKEY_LOCAL_MACHINE.</summary>
    public IReadOnlyList<RemovalOutcome> Remove(IEnumerable<RegistryTarget> targets)
    {
        var outcomes = new List<RemovalOutcome>();
        int index = 0;
        foreach (var target in targets)
        {
            var outcome = RemoveOne(target, ++index);
            _log?.Record(Mode, outcome);
            outcomes.Add(outcome);
        }
        return outcomes;
    }

    private RemovalOutcome RemoveOne(RegistryTarget target, int index)
    {
        string label = target.ToString();
        if (!IsAllowed(target)) return new RemovalOutcome(label, 0, RemovalError.OutsideAllowedRoots);
        string key = Normalize(target.KeyPath)!;
        using var opened = Open(key, writable: false);
        if (opened is null) return new RemovalOutcome(label, 0, RemovalError.NotFound);
        if (target.IsValue && opened.GetValue(target.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is null
            && !opened.GetValueNames().Contains(target.ValueName, StringComparer.OrdinalIgnoreCase))
            return new RemovalOutcome(label, 0, RemovalError.NotFound);
        if (Mode == RemovalMode.DryRun) return new RemovalOutcome(label, 0, null);

        // The backup must exist before anything is deleted.
        string file = Path.Combine(BackupFolder, $"{index:000}.reg");
        if (!Export(key, file)) return new RemovalOutcome(label, 0, RemovalError.Failed, "Backup non riuscito: nulla è stato cancellato");

        try
        {
            if (target.IsValue)
            {
                using var writable = Open(key, writable: true);
                if (writable is null) return new RemovalOutcome(label, 0, RemovalError.AccessDenied);
                writable.DeleteValue(target.ValueName!, throwOnMissingValue: false);
            }
            else
            {
                int slash = key.LastIndexOf('\\');
                using var parent = Open(key[..slash], writable: true);
                if (parent is null) return new RemovalOutcome(label, 0, RemovalError.AccessDenied);
                parent.DeleteSubKeyTree(key[(slash + 1)..], throwOnMissingSubKey: false);
            }
            return new RemovalOutcome(label, 0, null, file);
        }
        catch (UnauthorizedAccessException e) { return new RemovalOutcome(label, 0, RemovalError.AccessDenied, e.Message); }
        catch (System.Security.SecurityException e) { return new RemovalOutcome(label, 0, RemovalError.AccessDenied, e.Message); }
        catch (Exception e) when (e is IOException or ArgumentException) { return new RemovalOutcome(label, 0, RemovalError.Failed, e.Message); }
    }

    /// <summary>Opens a key in the 64-bit view (WOW6432Node paths are used as they are).</summary>
    public static RegistryKey? Open(string fullPath, bool writable)
    {
        var key = Normalize(fullPath);
        if (key is null) return null;
        int slash = key.IndexOf('\\');
        var hive = key.StartsWith("HKEY_CURRENT_USER", StringComparison.Ordinal) ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        try
        {
            return slash < 0 ? null : root.OpenSubKey(key[(slash + 1)..], writable);
        }
        catch (System.Security.SecurityException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>reg.exe export of the whole key, so a double click restores it.</summary>
    public static bool Export(string key, string file)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var reg = Path.Combine(Environment.SystemDirectory, "reg.exe");
            var info = new ProcessStartInfo(reg) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "export", key, file, "/y", "/reg:64" }) info.ArgumentList.Add(arg);
            ProcessEnvironment.Sanitize(info);
            using var p = Process.Start(info)!;
            p.WaitForExit(60_000);
            return p.HasExited && p.ExitCode == 0 && new FileInfo(file).Length > 0;
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
