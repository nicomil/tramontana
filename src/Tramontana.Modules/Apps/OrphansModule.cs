using System.Diagnostics;
using Microsoft.Win32;
using Tramontana.Core;

namespace Tramontana.Modules.Apps;

/// <summary>
/// Folders left by programs that are no longer installed: program folders in
/// Program Files and %LOCALAPPDATA%\Programs that no installed program,
/// service, Store app or running process uses, and data folders in AppData
/// and ProgramData untouched for six months whose name matches nothing
/// installed. Nothing is preselected: on Windows a folder name does not
/// identify its owner for certain.
/// </summary>
public sealed class OrphansModule : ICleanerModule
{
    public string Id => "orphans";
    public string Title => "Avanzi di programmi rimossi";

    public IReadOnlyList<string> AllowedRoots =>
        [KnownPaths.RoamingAppData, KnownPaths.LocalAppData, KnownPaths.LocalAppDataLow];

    private static readonly HashSet<string> KnownSystemFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Packages", "Temp", "Comms", "ConnectedDevicesPlatform", "D3DSCache", "NVIDIA", "NVIDIA Corporation",
        "AMD", "Intel", "Programs", "Publishers", "PlaceholderTileLogoFolder", "CrashDumps", "Microsoft Help", "VirtualStore",
        "PeerDistRepub", "Diagnostics", "History", "IsolatedStorage", "Application Data", "Microsoft_Corporation",
        "Tramontana", "WinCleaner", "Package Cache", "Packages", "ssh", "regid.1991-06.com.microsoft", "USOShared", "USOPrivate", "SoftwareDistribution",
        "WindowsHolographicDevices", "Windows", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail",
        "Windows Media Player", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "Windows Sidebar",
        "WindowsApps", "WindowsPowerShell", "Common Files", "Internet Explorer", "ModifiableWindowsApps", "Reference Assemblies",
        "Uninstall Information", "Microsoft Update Health Tools", "Microsoft.NET", "MSBuild", "dotnet", "PackageManagement",
        "Desktop", "Documents", "Templates", "Start Menu", "Favorites", "Mozilla", "Google", "Adobe", "Apple", "Apple Computer",
        "Sun", "Oracle", "Java", "Steam", "Spotify", "Discord", "Zoom", "Slack", "JetBrains", "Code", "npm", "npm-cache",
        "pip", "NuGet", "Yarn", "pnpm", "go-build", "electron", "electron-builder", "ms-playwright", "OneDrive", "Teams",
        "SquirrelTemp", "Mozilla Firefox", "Opera Software", "BraveSoftware", "Vivaldi", "Chromium", "Packages",
        "Device Stage", "DeviceSync", "Ssh", "SystemData", "regid.1991-06.com.microsoft", "Sophia", "Comms", "MicrosoftEdge",
        "Downloaded Installations", "Downloaded Program Files", "Installer", "Setup", "Updater", "Update",
    };

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        progress?.Report("Raccolta di programmi, servizi e app in uso…");
        var installed = InstalledPrograms.All();
        var owners = Owners(installed);
        var names = new HashSet<string>(installed.SelectMany(p => LeftoverFinder.CandidateNames(p).Concat(LeftoverFinder.PublisherNames(p))),
            StringComparer.OrdinalIgnoreCase);
        foreach (var p in installed.Where(p => p.PackageFamilyName is not null))
            names.Add(p.PackageFamilyName!.Split('_')[0].Split('.').Last());
        foreach (var process in Process.GetProcesses()) { try { names.Add(process.ProcessName); } catch { } process.Dispose(); }

        bool Owned(string folder) => owners.Any(o => PathGuard.IsSameOrInside(o, folder) || PathGuard.IsSameOrInside(folder, o));

        var programItems = new List<ScanItem>();
        foreach (var (root, admin) in new[] { (KnownPaths.ProgramFiles, true), (KnownPaths.ProgramFilesX86, true), (Path.Combine(KnownPaths.LocalAppData, "Programs"), false) })
        {
            foreach (var folder in Subfolders(root))
            {
                cancellation.ThrowIfCancellationRequested();
                string name = Path.GetFileName(folder);
                if (KnownSystemFolders.Contains(name) || Owned(folder)) continue;
                if (IsSystemOwned(folder)) continue;
                // A vendor folder ("Program Files\Vendor\App"): look one level down.
                var children = Subfolders(folder).ToList();
                bool vendor = children.Count > 0 && !Directory.EnumerateFiles(folder, "*.exe").Any();
                foreach (var candidate in vendor ? children : [folder])
                {
                    if (Owned(candidate) || KnownSystemFolders.Contains(Path.GetFileName(candidate))) continue;
                    if (names.Contains(Path.GetFileName(candidate))) continue;
                    var size = FileWalker.Measure(candidate, cancellation);
                    programItems.Add(new ScanItem(candidate, size.Bytes, RiskLevel.High, false, admin,
                        $"Nessun programma installato usa questa cartella · modificata {UserFilesWalker.Age(size.NewestWriteUtc)}", size.NewestWriteUtc));
                }
            }
        }

        var dataItems = new List<ScanItem>();
        var limit = DateTime.UtcNow.AddDays(-180);
        foreach (var (root, admin) in new[] { (KnownPaths.RoamingAppData, false), (KnownPaths.LocalAppData, false), (KnownPaths.LocalAppDataLow, false), (KnownPaths.ProgramData, true) })
        {
            foreach (var folder in Subfolders(root))
            {
                cancellation.ThrowIfCancellationRequested();
                string name = Path.GetFileName(folder);
                if (name.StartsWith('.') || name.StartsWith('{') || KnownSystemFolders.Contains(name) || names.Contains(name) || Owned(folder)) continue;
                if (names.Any(n => n.Length >= 4 && (name.StartsWith(n, StringComparison.OrdinalIgnoreCase) || n.StartsWith(name, StringComparison.OrdinalIgnoreCase)))) continue;
                var size = FileWalker.Measure(folder, cancellation);
                if (size.NewestWriteUtc > limit || size.Bytes == 0) continue;
                dataItems.Add(new ScanItem(folder, size.Bytes, RiskLevel.High, false, admin,
                    $"Nessun programma installato con questo nome · non modificata da {UserFilesWalker.Age(size.NewestWriteUtc).Replace(" fa", "")}", size.NewestWriteUtc));
            }
        }

        var categories = new List<ScanCategory>();
        if (programItems.Count > 0)
            categories.Add(new ScanCategory("orphan-programs", "Cartelle di programmi non più installati", [.. programItems.OrderByDescending(i => i.Size)])
            { Group = "orphans", Description = "Controlla il nome prima di rimuoverle." });
        if (dataItems.Count > 0)
            categories.Add(new ScanCategory("orphan-data", "Dati di programmi non più installati", [.. dataItems.OrderByDescending(i => i.Size)])
            { Group = "orphans", Description = "Cartelle in AppData e ProgramData ferme da più di sei mesi. Possono contenere salvataggi o documenti." });
        return new ScanReport(Id, categories);
    }, cancellation);

    /// <summary>Folders used by installed programs, services and Store apps.</summary>
    private static List<string> Owners(IReadOnlyList<InstalledProgram> installed)
    {
        var owners = new List<string>();
        foreach (var p in installed)
        {
            if (p.InstallLocation is { } l) owners.Add(l);
            foreach (var command in new[] { p.DisplayIcon, p.UninstallString })
                if (InstalledPrograms.ExecutablePath(command) is { } exe && Path.GetDirectoryName(exe) is { } dir && !InstalledPrograms.IsSharedFolder(dir))
                    owners.Add(dir);
        }
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (var name in services?.GetSubKeyNames() ?? [])
            {
                using var key = services!.OpenSubKey(name);
                if (InstalledPrograms.ExecutablePath(key?.GetValue("ImagePath") as string) is { } exe && Path.GetDirectoryName(exe) is { } dir
                    && !InstalledPrograms.IsSharedFolder(dir))
                    owners.Add(dir);
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or IOException) { }
        foreach (var process in Process.GetProcesses())
        {
            try { if (process.MainModule?.FileName is { } f && Path.GetDirectoryName(f) is { } dir) owners.Add(dir); } catch { }
            process.Dispose();
        }
        return owners.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IEnumerable<string> Subfolders(string root)
    {
        if (!Directory.Exists(root)) return [];
        try
        {
            return new DirectoryInfo(root).EnumerateDirectories()
                .Where(d => !d.Attributes.HasFlag(FileAttributes.ReparsePoint))
                .Select(d => d.FullName).ToList();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return []; }
    }

    private static bool IsSystemOwned(string folder)
    {
        try
        {
            using var handle = PinnedFileSystem.OpenDirectoryPath(folder, PinnedFileSystem.DirectoryReadAccess | 0x0002_0000u /* READ_CONTROL */);
            return PinnedFileSystem.IsOwnedByTrustedInstaller(handle);
        }
        catch (IOException) { return true; }
    }
}
