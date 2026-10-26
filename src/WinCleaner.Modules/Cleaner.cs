using WinCleaner.Core;

namespace WinCleaner.Modules;

/// <summary>Runs the removal of chosen items for a module.</summary>
public static class Cleaner
{
    /// <summary>
    /// Removes user-level items (items that need administrator rights must go
    /// through the elevated helper and are refused here).
    /// </summary>
    public static IReadOnlyList<RemovalOutcome> CleanUserItems(ICleanerModule module, IReadOnlyList<ScanItem> items,
        RemovalMode mode, IProgress<RemovalOutcome>? progress = null, CancellationToken cancellation = default)
    {
        var userItems = items.Where(i => !i.NeedsAdmin).ToList();
        var refused = items.Where(i => i.NeedsAdmin)
            .Select(i => new RemovalOutcome(i.Path, 0, RemovalError.AccessDenied, "Richiede l'amministratore"));
        IReadOnlyList<RemovalOutcome> done = module is ICustomCleaner custom
            ? custom.Clean(userItems, mode, cancellation)
            : Roots.UserRemover(module.AllowedRoots, mode).Remove(userItems.Select(i => i.Path), progress, cancellation);
        return [.. done, .. refused];
    }
}
