using System.Text.RegularExpressions;
using WinCleaner.Core;

namespace WinCleaner.Modules.Apps;

/// <summary>
/// Finds the files, shortcuts and registry keys a program leaves behind.
///
/// Matching is strict: a folder or key must be named exactly like the
/// program (with or without its version), like its install folder, or sit
/// under the publisher's folder with such a name. Generic names, names of
/// other installed programs and anything inside another program's folder are
/// never returned. Only the install folder left by the uninstaller and
/// shortcuts to missing files are preselected: data folders and settings may
/// hold the user's work.
/// </summary>
public static partial class LeftoverFinder
{
    private static readonly HashSet<string> GenericNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Google", "Common", "Common Files", "Programs", "Packages", "Temp", "Cache", "Caches",
        "Logs", "Data", "Microsoft Corporation", "Mozilla", "Apple", "Intel", "NVIDIA", "AMD", "App", "Apps", "Application",
        "Update", "Updater", "Installer", "Setup", "Software", "Tools", "Users", "Public", "Default", "Local", "Roaming",
        "LocalLow", "Crashpad", "CrashDumps", "Package Cache", "Help", "Uninstall", "bin", "x64", "x86",
    };

    /// <summary>"Opera Stable 131.0.5877.116" → "Opera Stable"; "Python 3.13.1 (64-bit)" → "Python".</summary>
    public static string NormalizeName(string name)
    {
        var s = ArchitectureSuffix().Replace(name, "");
        s = VersionSuffix().Replace(s, "");
        return s.Trim(' ', '-', '_', '.', ',');
    }

    [GeneratedRegex(@"\s*[\(\[]?\b(x64|x86|arm64|64[- ]?bit|32[- ]?bit|user|machine|utente)\b[\)\]]?", RegexOptions.IgnoreCase)]
    private static partial Regex ArchitectureSuffix();

    [GeneratedRegex(@"\s*(v(ersion)?\s*)?\d+(\.\d+)+.*$|\s+\d+$", RegexOptions.IgnoreCase)]
    private static partial Regex VersionSuffix();

    /// <summary>Names a leftover of <paramref name="program"/> may have.</summary>
    internal static HashSet<string> CandidateNames(InstalledProgram program)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { program.Name, NormalizeName(program.Name) };
        if (program.InstallLocation is { } location) names.Add(Path.GetFileName(location));
        names.RemoveWhere(n => n.Length < 3 || GenericNames.Contains(n));
        return names;
    }

    /// <summary>Folder names the publisher may use as a parent: "VideoLAN", "Mozilla"…</summary>
    internal static HashSet<string> PublisherNames(InstalledProgram program)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(program.Publisher))
        {
            names.Add(program.Publisher.Trim());
            names.Add(CompanySuffix().Replace(program.Publisher, "").Trim(' ', ',', '.'));
        }
        if (program.InstallLocation is { } location && Path.GetDirectoryName(location) is { } parent
            && !InstalledPrograms.IsSharedFolder(parent))
            names.Add(Path.GetFileName(parent));
        names.RemoveWhere(n => n.Length < 2);
        return names;
    }

    [GeneratedRegex(@"[,.]?\s*\b(inc|llc|ltd|gmbh|s\.?r\.?l|s\.?p\.?a|corp|corporation|co|ag|sa|bv|limited)\b\.?$", RegexOptions.IgnoreCase)]
    private static partial Regex CompanySuffix();

    public static ScanReport Find(InstalledProgram program, IReadOnlyList<InstalledProgram> installed, bool uninstalled)
    {
        var others = installed.Where(p => p.Id != program.Id).ToList();
        var otherNames = new HashSet<string>(others.SelectMany(CandidateNames), StringComparer.OrdinalIgnoreCase);
        var otherLocations = others.Select(p => p.InstallLocation).OfType<string>().ToList();
        var names = CandidateNames(program);
        names.RemoveWhere(otherNames.Contains);
        var publishers = PublisherNames(program);

        bool BelongsToOther(string path) =>
            otherLocations.Any(l => PathGuard.IsSameOrInside(path, l) || PathGuard.IsStrictlyInside(l, path));
        // While the program is installed its own folder is the program, not a leftover.
        bool IsProgramItself(string path) => !uninstalled && program.InstallLocation is { } own &&
            (PathGuard.IsSameOrInside(path, own) || PathGuard.IsStrictlyInside(own, path));

        var files = new List<ScanItem>();
        var shortcuts = new List<ScanItem>();
        var registry = new List<ScanItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddFolder(string path, bool admin, bool preselect, string detail)
        {
            if (!Directory.Exists(path) && !File.Exists(path)) return;
            if (BelongsToOther(path) || IsProgramItself(path) || !seen.Add(path)) return;
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) return;
            var size = FileWalker.Measure(path);
            files.Add(new ScanItem(path, size.Bytes, preselect ? RiskLevel.Medium : RiskLevel.High, preselect, admin, detail, size.NewestWriteUtc));
        }

        // The install folder, when the uninstaller left it behind.
        if (uninstalled && program.InstallLocation is { } location && Directory.Exists(location) && !InstalledPrograms.IsSharedFolder(location))
            AddFolder(location, !PathGuard.IsStrictlyInside(location, KnownPaths.UserProfile), true, "Cartella del programma rimasta");

        // Data folders.
        var bases = new (string Path, bool Admin)[]
        {
            (KnownPaths.RoamingAppData, false), (KnownPaths.LocalAppData, false), (KnownPaths.LocalAppDataLow, false),
            (Path.Combine(KnownPaths.LocalAppData, "Programs"), false), (KnownPaths.ProgramData, true),
            (KnownPaths.ProgramFiles, true), (KnownPaths.ProgramFilesX86, true),
        };
        foreach (var (basePath, admin) in bases)
        {
            if (!Directory.Exists(basePath)) continue;
            foreach (var name in names)
                AddFolder(Path.Combine(basePath, name), admin, false, "Dati o impostazioni del programma");
            foreach (var publisher in publishers.Where(p => !GenericNames.Contains(p)))
                foreach (var name in names)
                    AddFolder(Path.Combine(basePath, publisher, name), admin, false, "Dati o impostazioni del programma");
        }

        // Shortcuts that point into the install folder (or nowhere).
        if (program.InstallLocation is { } target)
        {
            foreach (var (folder, admin) in new[]
            {
                (KnownPaths.StartMenu, false), (KnownPaths.CommonStartMenu, true),
                (KnownPaths.Desktop, false), (Path.Combine(KnownPaths.Public, "Desktop"), true),
            })
            {
                if (!Directory.Exists(folder)) continue;
                IEnumerable<string> links;
                try { links = Directory.EnumerateFiles(folder, "*.lnk", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = 4 }).ToList(); }
                catch (IOException) { continue; }
                foreach (var link in links)
                {
                    var linkTarget = Shortcuts.Target(link);
                    if (linkTarget is null || !PathGuard.IsStrictlyInside(linkTarget, target) || !seen.Add(link)) continue;
                    bool missing = !File.Exists(linkTarget);
                    if (!uninstalled && !missing) continue;
                    shortcuts.Add(new ScanItem(link, new FileInfo(link).Length, RiskLevel.Low, missing, admin,
                        missing ? "Collegamento a un file che non esiste più" : "Collegamento al programma"));
                }
            }
        }

        // Settings in the registry.
        foreach (var hive in new[] { @"HKEY_CURRENT_USER\Software", @"HKEY_LOCAL_MACHINE\SOFTWARE", @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node" })
        {
            bool admin = hive.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.Ordinal);
            var keys = names.Select(n => $@"{hive}\{n}")
                .Concat(publishers.SelectMany(p => names.Select(n => $@"{hive}\{p}\{n}")));
            foreach (var key in keys)
            {
                if (!seen.Add(key) || !RegistryCleaner.IsAllowed(new RegistryTarget(key))) continue;
                using var opened = RegistryCleaner.Open(key, writable: false);
                if (opened is null) continue;
                registry.Add(new ScanItem(key, 0, RiskLevel.High, false, admin, "Impostazioni nel registro") { Kind = ItemKind.RegistryKey });
            }
        }
        if (uninstalled && program.RegistryKey is { } uninstallKey && InstalledPrograms.ExecutablePath(program.UninstallString) is null)
        {
            using var opened = RegistryCleaner.Open(uninstallKey, writable: false);
            if (opened is not null)
                registry.Add(new ScanItem(uninstallKey, 0, RiskLevel.Low, true, !program.PerUser,
                    "Voce di disinstallazione rimasta (il programma non c'è più)") { Kind = ItemKind.RegistryKey, Label = "Voce in App installate" });
        }

        var categories = new List<ScanCategory>();
        if (files.Count > 0) categories.Add(new ScanCategory("leftover-files", "File e cartelle", files) { Group = "leftovers" });
        if (shortcuts.Count > 0) categories.Add(new ScanCategory("leftover-shortcuts", "Collegamenti", shortcuts) { Group = "leftovers" });
        if (registry.Count > 0) categories.Add(new ScanCategory("leftover-registry", "Registro di sistema", registry) { Group = "leftovers" });
        return new ScanReport("leftovers", categories);
    }

    /// <summary>Roots for removing leftovers: user data, plus the program folders (admin).</summary>
    public static IReadOnlyList<string> AllowedRoots(InstalledProgram program)
    {
        var roots = new List<string>
        {
            KnownPaths.RoamingAppData, KnownPaths.LocalAppData, KnownPaths.LocalAppDataLow,
            KnownPaths.StartMenu, KnownPaths.Desktop,
        };
        if (program.InstallLocation is { } l && PathGuard.IsStrictlyInside(l, KnownPaths.UserProfile)
            && Path.GetDirectoryName(l) is { } parent) roots.Add(parent);
        return roots;
    }

    /// <summary>System roots for leftovers (removed by the elevated helper).</summary>
    public static IReadOnlyList<string> SystemRoots() =>
    [
        KnownPaths.ProgramFiles, KnownPaths.ProgramFilesX86, KnownPaths.ProgramData,
        KnownPaths.CommonStartMenu, Path.Combine(KnownPaths.Public, "Desktop"),
    ];
}
