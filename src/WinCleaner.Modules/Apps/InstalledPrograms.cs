using System.Globalization;
using Microsoft.Win32;
using WinCleaner.Core;

namespace WinCleaner.Modules.Apps;

public enum ProgramSource { Desktop, Store }

/// <summary>A program listed in Settings → Apps.</summary>
public sealed record InstalledProgram
{
    /// <summary>Stable id: the registry key path, or "msix:" + package full name.</summary>
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Publisher { get; init; }
    public string? Version { get; init; }
    public DateTime? InstallDate { get; init; }
    /// <summary>Install folder, from the registry or inferred from the icon or the uninstaller.</summary>
    public string? InstallLocation { get; init; }
    public long Size { get; init; }
    public string? UninstallString { get; init; }
    public string? QuietUninstallString { get; init; }
    public string? DisplayIcon { get; init; }
    /// <summary>Windows Installer product code ({GUID}) for MSI packages.</summary>
    public string? ProductCode { get; init; }
    public ProgramSource Source { get; init; }
    /// <summary>Full registry path of the Uninstall entry (desktop programs).</summary>
    public string? RegistryKey { get; init; }
    public bool PerUser { get; init; }
    public bool Is32Bit { get; init; }
    public bool NoRemove { get; init; }
    public string? PackageFullName { get; init; }
    public string? PackageFamilyName { get; init; }
    public DateTime? LastUsedUtc { get; init; }

    /// <summary>Removing it needs administrator rights (machine-wide install).</summary>
    public bool NeedsAdmin => Source == ProgramSource.Desktop && !PerUser;
}

/// <summary>Lists installed desktop programs (Uninstall keys) and Store apps.</summary>
public static class InstalledPrograms
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public static List<InstalledProgram> All(bool includeStore = true)
    {
        var lastUsed = UserAssist.LastRunByPath();
        var prefetch = UserAssist.LastRunByExeName();
        var list = new List<InstalledProgram>();
        list.AddRange(Desktop(RegistryHive.LocalMachine, RegistryView.Registry64, lastUsed, prefetch));
        list.AddRange(Desktop(RegistryHive.LocalMachine, RegistryView.Registry32, lastUsed, prefetch));
        list.AddRange(Desktop(RegistryHive.CurrentUser, RegistryView.Default, lastUsed, prefetch));
        if (includeStore) list.AddRange(StoreApps.List());
        // The same MSI can appear in both views or twice per user: keep one.
        return list
            .GroupBy(p => p.ProductCode ?? p.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static IEnumerable<InstalledProgram> Desktop(RegistryHive hive, RegistryView view, Dictionary<string, DateTime> lastUsed,
        Dictionary<string, DateTime> prefetch)
    {
        using var root = RegistryKey.OpenBaseKey(hive, view);
        using var uninstall = root.OpenSubKey(UninstallPath);
        if (uninstall is null) yield break;
        string hiveName = hive == RegistryHive.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER";
        bool is32 = hive == RegistryHive.LocalMachine && view == RegistryView.Registry32;
        string keyBase = hiveName + @"\" + (is32 ? @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" : UninstallPath);
        foreach (var name in uninstall.GetSubKeyNames())
        {
            InstalledProgram? program = null;
            try
            {
                using var key = uninstall.OpenSubKey(name);
                if (key is not null) program = Read(key, name, keyBase + @"\" + name, hive == RegistryHive.CurrentUser, is32, lastUsed, prefetch);
            }
            catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException) { }
            if (program is not null) yield return program;
        }
    }

    internal static InstalledProgram? Read(RegistryKey key, string keyName, string fullPath, bool perUser, bool is32,
        Dictionary<string, DateTime> lastUsed, Dictionary<string, DateTime>? prefetch = null)
    {
        string? displayName = (key.GetValue("DisplayName") as string)?.Trim();
        if (string.IsNullOrEmpty(displayName)) return null;
        if (key.GetValue("SystemComponent") is int system && system == 1) return null;
        if (key.GetValue("ParentKeyName") is string { Length: > 0 }) return null; // updates of another product
        if (key.GetValue("ReleaseType") is string release && (release.Contains("Update", StringComparison.OrdinalIgnoreCase) || release.Contains("Hotfix", StringComparison.OrdinalIgnoreCase))) return null;
        string? uninstall = key.GetValue("UninstallString") as string;
        string? quiet = key.GetValue("QuietUninstallString") as string;
        if (string.IsNullOrWhiteSpace(uninstall) && string.IsNullOrWhiteSpace(quiet)) return null;

        bool isMsi = key.GetValue("WindowsInstaller") is int msi && msi == 1;
        string? productCode = isMsi && Guid.TryParse(keyName, out _) ? keyName.ToUpperInvariant() : null;
        string? icon = key.GetValue("DisplayIcon") as string;
        string? location = Clean(key.GetValue("InstallLocation") as string);
        if (location is null || !Directory.Exists(location)) location = InferLocation(icon, uninstall);

        long size = key.GetValue("EstimatedSize") is int kb && kb > 0 ? kb * 1024L : 0;
        DateTime? installed = null;
        if (key.GetValue("InstallDate") is string date &&
            DateTime.TryParseExact(date, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
            installed = d;

        DateTime? used = null;
        if (location is not null)
        {
            foreach (var (path, when) in lastUsed)
                if (PathGuard.IsStrictlyInside(path, location) && (used is null || when > used)) used = when;
            if (prefetch is { Count: > 0 })
            {
                try
                {
                    foreach (var exe in Directory.EnumerateFiles(location, "*.exe", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2, IgnoreInaccessible = true }))
                        if (prefetch.TryGetValue(Path.GetFileName(exe), out var when) && (used is null || when > used)) used = when;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
        }

        return new InstalledProgram
        {
            Id = fullPath,
            Name = displayName,
            Publisher = (key.GetValue("Publisher") as string)?.Trim(),
            Version = (key.GetValue("DisplayVersion") as string)?.Trim(),
            InstallDate = installed,
            InstallLocation = location,
            Size = size,
            UninstallString = uninstall,
            QuietUninstallString = quiet,
            DisplayIcon = icon,
            ProductCode = productCode,
            Source = ProgramSource.Desktop,
            RegistryKey = fullPath,
            PerUser = perUser,
            Is32Bit = is32,
            NoRemove = key.GetValue("NoRemove") is int noRemove && noRemove == 1,
            LastUsedUtc = used,
        };
    }

    /// <summary>Strips quotes and a trailing backslash; null for empty or invalid paths.</summary>
    internal static string? Clean(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        path = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"').Trim());
        if (path.Length > 3) path = path.TrimEnd('\\');
        return PathGuard.IsValidPath(path) ? path : null;
    }

    /// <summary>
    /// Install folder from the icon or the uninstaller executable, when the
    /// registry has none. Shared folders (Windows, the Installer cache,
    /// Package Cache, Program Files itself) are never returned.
    /// </summary>
    internal static string? InferLocation(string? icon, string? uninstall)
    {
        foreach (var candidate in new[] { ExecutablePath(icon), ExecutablePath(uninstall) })
        {
            if (candidate is null) continue;
            string? folder = Path.GetDirectoryName(candidate);
            if (folder is null || !Directory.Exists(folder) || IsSharedFolder(folder)) continue;
            return folder;
        }
        return null;
    }

    internal static bool IsSharedFolder(string folder)
    {
        string[] shared =
        [
            KnownPaths.Windows, KnownPaths.ProgramFiles, KnownPaths.ProgramFilesX86, KnownPaths.ProgramData,
            KnownPaths.LocalAppData, KnownPaths.RoamingAppData, KnownPaths.UserProfile, KnownPaths.Temp,
            Path.Combine(KnownPaths.ProgramFiles, "Common Files"), Path.Combine(KnownPaths.ProgramFilesX86, "Common Files"),
            Path.Combine(KnownPaths.LocalAppData, "Programs"),
        ];
        if (shared.Any(s => string.Equals(s, folder, StringComparison.OrdinalIgnoreCase))) return true;
        string[] sharedTrees =
        [
            KnownPaths.Windows,
            Path.Combine(KnownPaths.ProgramData, "Package Cache"),
            Path.Combine(KnownPaths.LocalAppData, "Package Cache"),
            Path.Combine(KnownPaths.ProgramData, "Microsoft"),
            KnownPaths.Temp,
        ];
        return sharedTrees.Any(s => PathGuard.IsSameOrInside(folder, s));
    }

    /// <summary>The executable at the start of a command line or icon reference ("C:\x\a.exe",0).</summary>
    internal static string? ExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        command = Environment.ExpandEnvironmentVariables(command.Trim());
        string path;
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end < 0) return null;
            path = command[1..end];
        }
        else
        {
            int exe = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            path = exe > 0 ? command[..(exe + 4)] : command.Split(',')[0];
        }
        path = path.Trim();
        return PathGuard.IsValidPath(path) && File.Exists(path) ? path : null;
    }

    /// <summary>Running processes whose executable is inside <paramref name="folder"/>.</summary>
    public static List<System.Diagnostics.Process> ProcessesIn(string folder)
    {
        var result = new List<System.Diagnostics.Process>();
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            string? path = null;
            try { path = p.MainModule?.FileName; } catch (Exception) { }
            if (path is not null && PathGuard.IsStrictlyInside(path, folder)) result.Add(p);
            else p.Dispose();
        }
        return result;
    }
}

/// <summary>
/// Last run time of programs from the UserAssist key (what Explorer records
/// for the Start menu), keyed by full executable path.
/// </summary>
public static class UserAssist
{
    private static readonly Dictionary<string, Func<string>> KnownFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = () => KnownPaths.ProgramFiles,
        ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = () => KnownPaths.ProgramFilesX86,
        ["{905e63b6-c1bf-494e-b29c-65b732d3d21a}"] = () => KnownPaths.ProgramFiles,
        ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = () => KnownPaths.Windows,
        ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = () => Environment.SystemDirectory,
        ["{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"] = () => Path.Combine(KnownPaths.Windows, "SysWOW64"),
        ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = () => KnownPaths.LocalAppData,
        ["{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"] = () => KnownPaths.RoamingAppData,
        ["{5E6C858F-0E22-4760-9AFE-EA3317B67173}"] = () => KnownPaths.UserProfile,
    };

    public static Dictionary<string, DateTime> LastRunByPath()
    {
        var result = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (root is null) return result;
            foreach (var guid in root.GetSubKeyNames())
            {
                using var count = root.OpenSubKey(guid + @"\Count");
                if (count is null) continue;
                foreach (var valueName in count.GetValueNames())
                {
                    if (count.GetValue(valueName) is not byte[] { Length: >= 68 } data) continue;
                    long time = BitConverter.ToInt64(data, 60);
                    if (time <= 0) continue;
                    string? path = Resolve(Rot13(valueName));
                    if (path is null) continue;
                    var when = DateTime.FromFileTimeUtc(time);
                    if (!result.TryGetValue(path, out var existing) || when > existing) result[path] = when;
                }
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or IOException or ArgumentOutOfRangeException) { }
        return result;
    }

    /// <summary>
    /// Last run by executable name from the Prefetch folder (EXE-HASH.pf is
    /// rewritten at each start). Readable only with administrator rights.
    /// </summary>
    public static Dictionary<string, DateTime> LastRunByExeName()
    {
        var result = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in new DirectoryInfo(Path.Combine(KnownPaths.Windows, "Prefetch")).EnumerateFiles("*.pf"))
            {
                int dash = file.Name.LastIndexOf('-');
                if (dash <= 0) continue;
                string exe = file.Name[..dash];
                if (!result.TryGetValue(exe, out var existing) || file.LastWriteTimeUtc > existing) result[exe] = file.LastWriteTimeUtc;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return result;
    }

    internal static string Rot13(string s) => string.Create(s.Length, s, (span, source) =>
    {
        for (int i = 0; i < source.Length; i++)
        {
            char c = source[i];
            span[i] = c switch
            {
                >= 'a' and <= 'z' => (char)('a' + (c - 'a' + 13) % 26),
                >= 'A' and <= 'Z' => (char)('A' + (c - 'A' + 13) % 26),
                _ => c,
            };
        }
    });

    private static string? Resolve(string name)
    {
        if (name.StartsWith('{'))
        {
            int end = name.IndexOf('}');
            if (end < 0 || !KnownFolders.TryGetValue(name[..(end + 1)], out var folder)) return null;
            name = folder() + name[(end + 1)..];
        }
        return PathGuard.IsValidPath(name) ? name : null;
    }
}
