namespace WinCleaner.Core;

/// <summary>Checks a selection before cleaning.</summary>
public static class Selection
{
    /// <summary>
    /// Groups of copies where the selection would remove the copy to keep or
    /// every copy. Cleaning must be refused when this is not empty.
    /// </summary>
    public static IReadOnlyList<ScanCategory> UnsafeCopyGroups(ScanReport report, IReadOnlySet<string> selected) =>
        report.Categories
            .Where(c => c.Keep is not null)
            .Where(c => selected.Contains(c.Keep!) || c.Items.All(i => selected.Contains(i.Path)))
            .ToList();

    /// <summary>The preselected items of a report.</summary>
    public static HashSet<string> Default(ScanReport report) =>
        new(report.AllItems.Where(i => i.AutoSelect).Select(i => i.Path), StringComparer.OrdinalIgnoreCase);
}
