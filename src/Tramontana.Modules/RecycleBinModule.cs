using Tramontana.Core;

namespace Tramontana.Modules;

/// <summary>
/// "Cestini": what is in the user's Recycle Bin on each fixed drive. Emptying
/// is always permanent; each item is listed with its original path and the
/// date it was deleted.
/// </summary>
public sealed class RecycleBinModule : ICleanerModule, ICustomCleaner
{
    public string Id => "recycle-bin";
    public string Title => "Cestini";

    public IReadOnlyList<string> AllowedRoots =>
        [.. RecycleBin.FixedDrives().Select(d => $@"{d}:\$Recycle.Bin\{RecycleBin.CurrentUserSid}")];

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        var categories = new List<ScanCategory>();
        var unreadable = new List<string>();
        foreach (var drive in RecycleBin.FixedDrives())
        {
            cancellation.ThrowIfCancellationRequested();
            progress?.Report($"Cestino di {drive}:");
            List<RecycledItem> items;
            try { items = RecycleBin.List(drive); }
            catch (IOException) { unreadable.Add($@"{drive}:\$Recycle.Bin"); continue; }
            if (items.Count == 0) continue;
            categories.Add(new ScanCategory($"bin-{drive}", $"Cestino ({drive}:)",
                [.. items.OrderByDescending(i => i.DeletedUtc).Select(ToScanItem)])
            {
                Group = "bins",
                Description = "Lo svuotamento è definitivo.",
            });
        }
        return new ScanReport(Id, categories) { Unreadable = unreadable };
    }, cancellation);

    private static ScanItem ToScanItem(RecycledItem item) =>
        new(item.DataPath, item.Size, RiskLevel.High, AutoSelect: true, NeedsAdmin: false,
            Detail: $"{item.OriginalPath} · eliminato il {item.DeletedUtc.ToLocalTime():d MMM yyyy HH:mm}",
            LastWriteUtc: item.DeletedUtc)
        { Label = Path.GetFileName(item.OriginalPath) };

    /// <summary>Permanently removes the chosen items and their records (the mode only matters for dry runs).</summary>
    public IReadOnlyList<RemovalOutcome> Clean(IReadOnlyList<ScanItem> items, RemovalMode mode, CancellationToken cancellation)
    {
        var outcomes = new List<RemovalOutcome>();
        var byDrive = items.GroupBy(i => char.ToUpperInvariant(i.Path[0]));
        foreach (var group in byDrive)
        {
            var current = RecycleBin.List(group.Key).ToDictionary(i => i.DataPath, StringComparer.OrdinalIgnoreCase);
            foreach (var item in group)
            {
                cancellation.ThrowIfCancellationRequested();
                RemovalOutcome outcome;
                if (!current.TryGetValue(item.Path, out var recycled))
                {
                    outcome = new RemovalOutcome(item.Path, 0, RemovalError.NotFound);
                }
                else if (mode == RemovalMode.DryRun)
                {
                    outcome = new RemovalOutcome(item.Path, recycled.Size, null);
                }
                else
                {
                    var stats = RecycleBin.Purge(recycled, cancellation);
                    outcome = stats.InUse + stats.Failed == 0
                        ? new RemovalOutcome(item.Path, stats.Bytes, null)
                        : new RemovalOutcome(item.Path, stats.Bytes, stats.InUse > 0 ? RemovalError.InUse : RemovalError.Failed, stats.FirstError);
                }
                OperationLog.Standard.Record(mode == RemovalMode.DryRun ? RemovalMode.DryRun : RemovalMode.Delete, outcome);
                outcomes.Add(outcome);
            }
        }
        return outcomes;
    }
}
