using WinCleaner.Core;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Protection.Checks;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// Runs every <see cref="IProtectionCheck"/> and merges the results. Nothing
/// is removed automatically: each finding explains itself and links to the
/// place to act on. See docs/spec/protection-upgrade.md.
/// </summary>
public static class ProtectionScanner
{
    public static IReadOnlyList<IProtectionCheck> DefaultChecks() =>
    [
        new DefencesCheck(), new DefenderCheck(), new PostureCheck(), new StartupCheck(), new WinlogonIfeoCheck(), new WmiBitsCheck(), new ComHijackCheck(),
        new ShellAndProvidersCheck(), new ScriptsAndOfficeCheck(), new HiddenTasksCheck(), new ServicesAndDriversCheck(), new RecentProgramsCheck(),
        new BrowserExtensionsCheck(), new BrowserHijackCheck(), new TrustedRootsCheck(), new NetworkConfigCheck(), new DevicesCheck(), new ProcessesCheck(), new SignatureScanCheck(),
    ];

    /// <summary>The scan as the screens use it: default context, baseline applied, ignored ids removed.</summary>
    public static List<Finding> Scan(IReadOnlyCollection<string>? ignored = null, IReadOnlyCollection<string>? trustedPublishers = null, SystemEvidence? evidence = null)
    {
        var context = new CheckContext
        {
            Evidence = evidence,
            TrustedPublishers = new HashSet<string>(trustedPublishers ?? [], StringComparer.OrdinalIgnoreCase),
        };
        var findings = Run(context, DefaultChecks());
        findings = ProtectionBaseline.Standard.Apply(findings, context.Now);
        if (ignored is { Count: > 0 }) findings.RemoveAll(f => ignored.Contains(f.Id));
        return findings;
    }

    /// <summary>Runs the checks whose requirements are met, in parallel, sorted by severity.</summary>
    public static List<Finding> Run(CheckContext context, IReadOnlyList<IProtectionCheck> checks)
    {
        var runnable = checks.Where(c => c.Requirement == CheckRequirement.None || context.Evidence is not null).ToList();
        var results = new List<Finding>[runnable.Count];
        Parallel.For(0, runnable.Count, new ParallelOptions { MaxDegreeOfParallelism = 4 }, i =>
        {
            try { results[i] = [.. runnable[i].Run(context)]; }
            catch (Exception e)
            {
                OperationLog.Standard.Write($"protection\tERR {runnable[i].Id}\t{e.Message}");
                results[i] = [];
            }
        });
        var seen = new HashSet<string>();
        return results.SelectMany(r => r)
            .Where(f => f.Publisher is null || !context.TrustedPublishers.Contains(f.Publisher) || f.Severity == Severity.Danger)
            .Where(f => seen.Add(f.Id))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => Array.IndexOf(Categories.Order, f.Category) is var i && i >= 0 ? i : 99)
            .ThenBy(f => f.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    /// <summary>Kept for the M4 callers and tests.</summary>
    internal static (Severity Severity, string Reason)? Assess(StartupItem item)
    {
        var verdict = StartupAssessor.Assess(item, new SystemSignatures(), KnownPaths.UserProfile);
        return verdict is null ? null : (verdict.Severity, verdict.Reason);
    }

    internal static IEnumerable<Finding> ChromiumExtensions(ChromiumBrowser browser, string profile) =>
        BrowserExtensionsCheck.ChromiumExtensions(browser, profile);

    /// <summary>Microsoft Defender's custom scan of one file or folder (runs as the user).</summary>
    public static async Task<string> DefenderScanPathAsync(string path, CancellationToken cancellation)
    {
        var mpcmd = Path.Combine(KnownPaths.ProgramFiles, "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mpcmd)) return "Microsoft Defender non è disponibile";
        if (!File.Exists(path) && !Directory.Exists(path)) return "File non trovato";
        var (exit, _) = await Maintenance.Exec(mpcmd, ["-Scan", "-ScanType", "3", "-File", path], cancellation);
        OperationLog.Standard.Write($"defender\tscan\t{path}\t{exit}");
        return exit switch
        {
            0 => "Defender non ha trovato minacce in questo file",
            2 => "Defender ha trovato una minaccia: controlla Sicurezza di Windows",
            _ => $"Analisi terminata con codice {exit}",
        };
    }

    /// <summary>Starts a Microsoft Defender quick scan and waits for it.</summary>
    public static async Task<string> DefenderQuickScanAsync(CancellationToken cancellation)
    {
        var mpcmd = Path.Combine(KnownPaths.ProgramFiles, "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mpcmd)) return "Microsoft Defender non è disponibile";
        var (exit, output) = await Maintenance.Exec(mpcmd, ["-Scan", "-ScanType", "1"], cancellation);
        return exit switch
        {
            0 => "Analisi rapida completata: nessuna minaccia",
            2 => "Defender ha trovato delle minacce: aprile in Sicurezza di Windows",
            _ => $"Analisi terminata con codice {exit}",
        };
    }
}
