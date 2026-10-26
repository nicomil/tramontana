using WinCleaner.Core;

namespace WinCleaner.Modules;

/// <summary>
/// "Pulizia sistema": temporary files, caches, logs and dumps of Windows,
/// browsers, apps and developer tools, from the JSON rules and the browser
/// catalog.
/// </summary>
public sealed class SystemJunkModule : ICleanerModule
{
    public string Id => "system-junk";
    public string Title => "Pulizia sistema";

    public IReadOnlyList<string> AllowedRoots => Roots.User();

    public static RuleSet LoadRules()
    {
        var assembly = typeof(SystemJunkModule).Assembly;
        using var stream = assembly.GetManifestResourceStream("WinCleaner.Rules.system-junk.json")
            ?? throw new InvalidOperationException("Missing system-junk.json");
        var set = RuleSet.Load(stream);
        return set with { Rules = [.. set.Rules, .. BrowserCatalog.CacheRules()] };
    }

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        progress?.Report("Analisi di file temporanei, cache e log…");
        var output = new RuleEngine().Evaluate(LoadRules(), cancellation);
        var notes = output.Notes.ToList();
        if (output.Unreadable.Any(p => Roots.System().Any(r => PathGuard.IsSameOrInside(p, r))))
            notes.Add("Alcune cartelle di sistema si leggono solo come amministratore: sblocca le funzioni di sistema per vederle.");
        return new ScanReport(Id, output.Categories) { Notes = notes, Unreadable = output.Unreadable };
    }, cancellation);
}
