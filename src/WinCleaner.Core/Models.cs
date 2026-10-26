namespace WinCleaner.Core;

/// <summary>How dangerous it is to remove an item.</summary>
public enum RiskLevel
{
    /// <summary>Regenerated automatically by Windows or the app.</summary>
    Low,
    /// <summary>Some state is lost (sessions, logins, faster startup).</summary>
    Medium,
    /// <summary>Possible data loss or a broken program.</summary>
    High,
}

/// <summary>A single file or folder found by a scan.</summary>
public sealed record ScanItem(
    string Path,
    long Size,
    RiskLevel Risk,
    bool AutoSelect,
    bool NeedsAdmin,
    string? Detail = null,
    DateTime? LastWriteUtc = null)
{
    public string DisplayName => System.IO.Path.GetFileName(Path) is { Length: > 0 } name ? name : Path;
}

/// <summary>A group of items of the same kind (for example "Temporary files").</summary>
public sealed record ScanCategory(string Id, string Title, IReadOnlyList<ScanItem> Items)
{
    /// <summary>
    /// For groups of copies (duplicates, similar photos): the item that must
    /// stay. Selecting the whole group never selects it, and a clean that would
    /// remove every item of the group is refused.
    /// </summary>
    public string? Keep { get; init; }

    /// <summary>Short explanation shown under the title.</summary>
    public string? Description { get; init; }

    /// <summary>Section of the screen the category belongs to (windows, browsers, apps, developer…).</summary>
    public string Group { get; init; } = "";

    public long TotalSize => Items.Sum(i => i.Size);
}

/// <summary>The result of scanning one module.</summary>
public sealed record ScanReport(string ModuleId, IReadOnlyList<ScanCategory> Categories)
{
    /// <summary>Folders that could not be read (usually missing permissions).</summary>
    public IReadOnlyList<string> Unreadable { get; init; } = [];

    /// <summary>Things the user should know, e.g. "Chrome is open: its cache was skipped".</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    public long TotalSize => Categories.Sum(c => c.TotalSize);
    public IEnumerable<ScanItem> AllItems => Categories.SelectMany(c => c.Items);
}

/// <summary>A feature that scans the PC and returns files to clean.</summary>
public interface ICleanerModule
{
    string Id { get; }
    string Title { get; }

    /// <summary>Folders this module may remove items from (see <see cref="SafeRemover"/>).</summary>
    IReadOnlyList<string> AllowedRoots { get; }

    Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation);
}
