using Tramontana.Core;

namespace Tramontana.Modules;

/// <summary>
/// The folders the modules may remove things from. Every rule path must fall
/// strictly under one of these (a root itself is never removed), or match one
/// of the single system items, which a test checks.
/// </summary>
public static class Roots
{
    /// <summary>Per-user folders cleaned without administrator rights.</summary>
    public static IReadOnlyList<string> User() =>
    [
        KnownPaths.LocalAppData,
        KnownPaths.RoamingAppData,
        KnownPaths.LocalAppDataLow,
        KnownPaths.Temp,
        Path.Combine(KnownPaths.UserProfile, ".gradle"),
        Path.Combine(KnownPaths.UserProfile, ".nuget"),
        Path.Combine(KnownPaths.UserProfile, ".m2"),
        Path.Combine(KnownPaths.UserProfile, ".cargo"),
        Path.Combine(KnownPaths.UserProfile, ".android"),
    ];

    /// <summary>System folders, cleaned only by the elevated helper.</summary>
    public static IReadOnlyList<string> System() =>
    [
        Path.Combine(KnownPaths.Windows, "Temp"),
        Path.Combine(KnownPaths.Windows, "SoftwareDistribution", "Download"),
        Path.Combine(KnownPaths.Windows, "Logs"),
        Path.Combine(KnownPaths.Windows, "debug"),
        Path.Combine(KnownPaths.Windows, "Minidump"),
        Path.Combine(KnownPaths.Windows, "LiveKernelReports"),
        Path.Combine(KnownPaths.Windows, "Prefetch"),
        Path.Combine(KnownPaths.ProgramData, "Microsoft", "Windows", "WER"),
        Path.Combine(KnownPaths.ProgramData, "NVIDIA Corporation", "Downloader"),
    ];

    /// <summary>Single system items outside the system folders (last component may use wildcards).</summary>
    public static IReadOnlyList<string> SystemItems() =>
    [
        Path.Combine(KnownPaths.Windows, "MEMORY.DMP"),
        Path.Combine(KnownPaths.SystemDrive, "FOUND.*"),
        Path.Combine(KnownPaths.SystemDrive, "$WINDOWS.~BT"),
        Path.Combine(KnownPaths.SystemDrive, "$WINDOWS.~WS"),
        Path.Combine(KnownPaths.SystemDrive, "$GetCurrent"),
        Path.Combine(KnownPaths.SystemDrive, "Windows10Upgrade"),
        Path.Combine(KnownPaths.SystemDrive, "AMD"),
    ];

    /// <summary>The user's own files (Desktop, Documents, Downloads and the other folders of the profile).</summary>
    public static IReadOnlyList<string> UserFiles()
    {
        var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "AppData", "Application Data", "Local Settings" };
        var roots = new List<string>();
        try
        {
            foreach (var dir in new DirectoryInfo(KnownPaths.UserProfile).EnumerateDirectories())
            {
                if (excluded.Contains(dir.Name) || dir.Name.StartsWith('.')) continue;
                if (dir.Attributes.HasFlag(FileAttributes.ReparsePoint) || dir.Attributes.HasFlag(FileAttributes.System)) continue;
                roots.Add(dir.FullName);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        // Known folders moved elsewhere (for example to OneDrive or another drive).
        foreach (var known in new[] { KnownPaths.Desktop, KnownPaths.Documents, KnownPaths.Downloads })
        {
            if (!string.IsNullOrEmpty(known) && Directory.Exists(known) && !roots.Any(r => PathGuard.IsSameOrInside(known, r)))
                roots.Add(known);
        }
        return roots;
    }

    /// <summary>Removal for user-level items of a module.</summary>
    public static SafeRemover UserRemover(IEnumerable<string> roots, RemovalMode mode) =>
        new(roots, mode, OperationLog.Standard);
}
