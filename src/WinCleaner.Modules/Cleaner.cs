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
        var userItems = items.Where(i => !i.NeedsAdmin && i.Kind != ItemKind.Info).ToList();
        var refused = items.Where(i => i.NeedsAdmin)
            .Select(i => new RemovalOutcome(i.Path, 0, RemovalError.AccessDenied, "Richiede l'amministratore"));
        var files = userItems.Where(i => i.Kind == ItemKind.File).ToList();
        var registry = userItems.Where(i => i.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue)
            .Select(i => new RegistryTarget(i.Path, i.Kind == ItemKind.RegistryValue ? i.ValueName ?? "" : null)).ToList();
        IReadOnlyList<RemovalOutcome> done = files.Count == 0 ? [] : module is ICustomCleaner custom
            ? custom.Clean(files, mode, cancellation)
            : Roots.UserRemover(module.AllowedRoots, mode).Remove(files.Select(i => i.Path), progress, cancellation);
        IReadOnlyList<RemovalOutcome> registryDone = registry.Count == 0 ? []
            : new RegistryCleaner(mode == RemovalMode.DryRun ? RemovalMode.DryRun : RemovalMode.Delete, OperationLog.Standard).Remove(registry);
        return [.. done, .. registryDone, .. refused];
    }
}
