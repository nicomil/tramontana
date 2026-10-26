using WinCleaner.Core;
using WinCleaner.Modules.Apps;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Programs that arrived in the last weeks: no publisher, unsigned
/// uninstaller, names that sell "optimization", or an autostart entry of
/// their own. Bundleware and adware come in exactly like this, signed or not.
/// </summary>
public sealed class RecentProgramsCheck(int days = 30) : IProtectionCheck
{
    public string Id => "recent-programs";
    public string Title => "Programmi installati di recente";

    private static readonly string[] PupWords = ["cleaner", "optimizer", "optimize", "speed", "booster", "boost", "driver updater", "driver update", "pc repair", "pc fix",
        "registry", "toolbar", "search protect", "web companion", "coupon", "savings", "weather", "pdf converter", "video converter", "free antivirus", "mcafee", "total av", "pc health", "mystart", "shopper"];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        var autostartPaths = new HashSet<string>(context.Startup.Where(s => s.Executable is not null).Select(s => s.Executable!), StringComparer.OrdinalIgnoreCase);
        foreach (var program in context.Programs)
        {
            if (program.InstallDate is not { } installed || (context.Now - installed).TotalDays > days) continue;
            if (program.Source == ProgramSource.Store) continue;
            var reasons = new List<string>();
            var severity = Severity.Info;
            string? uninstaller = program.UninstallString is { } u ? Performance.StartupManager.ExecutableOf(u) : null;
            var signature = uninstaller is not null && File.Exists(uninstaller) && !uninstaller.Contains("msiexec", StringComparison.OrdinalIgnoreCase) ? context.Signatures.Check(uninstaller) : null;
            if (string.IsNullOrWhiteSpace(program.Publisher)) { reasons.Add("Nessun editore dichiarato"); severity = Severity.Warning; }
            if (signature?.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid) { reasons.Add("Disinstallatore non firmato"); severity = Severity.Warning; }
            if (PupWords.Any(w => program.Name.Contains(w, StringComparison.OrdinalIgnoreCase))) { reasons.Add("Il nome promette pulizia, velocità o driver: tipico dei programmi indesiderati"); severity = Severity.Warning; }
            if (program.InstallLocation is { } location && autostartPaths.Any(p => PathGuard.IsStrictlyInside(p, location))) reasons.Add("Si è messo in avvio automatico");
            if (program.InstallLocation is { } loc && (PathGuard.IsStrictlyInside(loc, KnownPaths.LocalAppData) || PathGuard.IsStrictlyInside(loc, KnownPaths.RoamingAppData)) && string.IsNullOrWhiteSpace(program.Publisher))
            { reasons.Add("Installato in AppData senza chiedere l'amministratore"); severity = Severity.Warning; }
            if (reasons.Count == 0) reasons.Add("Installato di recente: controlla di averlo voluto tu");
            if (signature?.Publisher is not null && context.TrustedPublishers.Contains(signature.Publisher)) continue;
            list.Add(new Finding($"program|{program.Id}", Categories.Programs, program.Name, string.Join(". ", reasons) + ".", severity)
            {
                Path = program.InstallLocation ?? uninstaller,
                Evidence = [$"Installato il {installed:d}", $"Editore: {program.Publisher ?? "(nessuno)"}", $"Versione: {program.Version ?? "?"}",
                            $"Disinstallazione: {program.UninstallString ?? "?"}", signature?.Publisher is null ? "" : $"Disinstallatore firmato da: {signature.Publisher}"],
                Publisher = signature?.Publisher ?? program.Publisher,
            });
        }
        return list;
    }
}
