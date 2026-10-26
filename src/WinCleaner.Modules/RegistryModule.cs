using System.Runtime.InteropServices;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Apps;

namespace WinCleaner.Modules;

/// <summary>
/// "Registro": entries that point to things that no longer exist. Kept
/// deliberately narrow (Microsoft discourages broad registry cleaning): stale
/// Uninstall entries, App Paths and shared DLL counters to missing files, and
/// the MUI cache of removed programs. Every change is exported to a .reg file
/// first and can be undone with a double click.
/// </summary>
public sealed partial class RegistryModule : ICleanerModule
{
    public string Id => "registry";
    public string Title => "Registro";
    public IReadOnlyList<string> AllowedRoots => [];

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        var categories = new List<ScanCategory>();
        void Add(string id, string title, string description, List<ScanItem> items)
        {
            if (items.Count > 0) categories.Add(new ScanCategory(id, title, items) { Description = description, Group = "registry" });
        }
        progress?.Report("Controllo del registro…");
        Add("reg-uninstall", "Voci di programmi non più installati", "Compaiono in App installate ma il programma non c'è più.", StaleUninstallEntries());
        Add("reg-apppaths", "Percorsi di programmi mancanti", "Voci di App Paths che puntano a file inesistenti.", MissingAppPaths());
        Add("reg-shareddlls", "DLL condivise mancanti", "Contatori di librerie condivise che non esistono più.", MissingSharedDlls());
        Add("reg-muicache", "Nomi di programmi rimossi", "Cache dei nomi mostrati da Explorer per programmi che non esistono più.", StaleMuiCache());
        return new ScanReport(Id, categories);
    }, cancellation);

    private static bool Missing(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var exe = Performance.StartupManager.ExecutableOf(path);
        // Only plain local paths count: network or removable drives may just be disconnected.
        if (exe is null || !PathGuard.IsValidPath(exe)) return false;
        var drive = new DriveInfo(exe[..3]);
        try { if (drive.DriveType != DriveType.Fixed || !drive.IsReady) return false; } catch (IOException) { return false; }
        return !File.Exists(exe) && !Directory.Exists(exe);
    }

    private static List<ScanItem> StaleUninstallEntries()
    {
        var items = new List<ScanItem>();
        foreach (var (hive, view, path, admin) in new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", true),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", true),
            (RegistryHive.CurrentUser, RegistryView.Default, @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall", false),
        })
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            using var uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            foreach (var name in uninstall?.GetSubKeyNames() ?? [])
            {
                using var key = uninstall!.OpenSubKey(name);
                if (key?.GetValue("DisplayName") is not string display || display.Length == 0) continue;
                if (key.GetValue("SystemComponent") is int sc && sc == 1) continue;
                string? command = key.GetValue("UninstallString") as string;
                if (command is null) continue;
                if (command.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
                {
                    if (!Guid.TryParse(name, out _) || MsiQueryProductState(name) != -1 /* INSTALLSTATE_UNKNOWN */) continue;
                }
                else if (!Missing(command)) continue;
                string? location = InstalledPrograms.Clean(key.GetValue("InstallLocation") as string);
                if (location is not null && Directory.Exists(location)) continue;
                items.Add(new ScanItem($@"{path}\{name}", 0, RiskLevel.Low, true, admin, $"{display}: il programma di disinstallazione non esiste più")
                { Kind = ItemKind.RegistryKey, Label = display });
            }
        }
        return items;
    }

    [LibraryImport("msi.dll", EntryPoint = "MsiQueryProductStateW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int MsiQueryProductState(string product);

    private static List<ScanItem> MissingAppPaths()
    {
        var items = new List<ScanItem>();
        foreach (var (path, admin) in new[]
        {
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", true),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths", true),
            (@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths", false),
        })
        {
            using var root = RegistryCleaner.Open(path, writable: false);
            foreach (var name in root?.GetSubKeyNames() ?? [])
            {
                using var key = root!.OpenSubKey(name);
                if (key?.GetValue("") is string target && Missing(target))
                    items.Add(new ScanItem($@"{path}\{name}", 0, RiskLevel.Low, true, admin, $"Punta a {target}") { Kind = ItemKind.RegistryKey, Label = name });
            }
        }
        return items;
    }

    private static List<ScanItem> MissingSharedDlls()
    {
        var items = new List<ScanItem>();
        foreach (var path in new[]
        {
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs",
        })
        {
            using var key = RegistryCleaner.Open(path, writable: false);
            foreach (var value in key?.GetValueNames() ?? [])
            {
                if (Missing(value))
                    items.Add(new ScanItem(path, 0, RiskLevel.Low, true, true, value) { Kind = ItemKind.RegistryValue, ValueName = value, Label = Path.GetFileName(value) });
            }
        }
        return items;
    }

    private static List<ScanItem> StaleMuiCache()
    {
        var items = new List<ScanItem>();
        const string path = @"HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        using var key = RegistryCleaner.Open(path, writable: false);
        foreach (var value in key?.GetValueNames() ?? [])
        {
            // "C:\path\app.exe.FriendlyAppName" or ".ApplicationCompany"
            int dot = value.LastIndexOf('.');
            if (dot <= 0) continue;
            string file = value[..dot];
            if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
            if (Missing(file))
                items.Add(new ScanItem(path, 0, RiskLevel.Low, true, false, file) { Kind = ItemKind.RegistryValue, ValueName = value, Label = Path.GetFileName(file) });
        }
        return items;
    }
}
