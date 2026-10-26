using System.Text.Json;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// The ids seen by the previous scan, with the date each one first appeared.
/// Lets the screen say "new since last time", which on a PC that keeps
/// misbehaving is the most useful signal of all.
/// </summary>
public sealed class ProtectionBaseline(string filePath)
{
    public static ProtectionBaseline Standard { get; } =
        new(Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Protection", "last-scan.json"));

    private sealed record Entry(DateTime FirstSeen, DateTime LastSeen);
    private readonly object _lock = new();

    private Dictionary<string, Entry> Load()
    {
        try
        {
            if (File.Exists(filePath))
                return JsonSerializer.Deserialize<Dictionary<string, Entry>>(File.ReadAllText(filePath)) ?? [];
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        return [];
    }

    /// <summary>
    /// Marks the findings that were not in the previous scan and records the
    /// current ones. The first scan ever marks nothing as new. Ids no longer
    /// found are forgotten after 90 days, so one that comes back after a long
    /// time counts as new again. Findings of severity Ok are never "new".
    /// </summary>
    public List<Finding> Apply(IEnumerable<Finding> findings, DateTime now)
    {
        lock (_lock)
        {
            var stored = Load();
            bool firstScan = stored.Count == 0;
            var previous = stored.Where(e => (now - e.Value.LastSeen).TotalDays < 90).ToDictionary(e => e.Key, e => e.Value);
            var next = new Dictionary<string, Entry>(previous);
            var marked = new List<Finding>();
            foreach (var finding in findings)
            {
                if (previous.TryGetValue(finding.Id, out var entry))
                {
                    marked.Add(finding with { FirstSeen = entry.FirstSeen, IsNew = false });
                    next[finding.Id] = entry with { LastSeen = now };
                }
                else
                {
                    marked.Add(finding with { FirstSeen = now, IsNew = !firstScan && finding.Severity > Severity.Ok });
                    next[finding.Id] = new Entry(now, now);
                }
            }
            Save(next);
            return marked;
        }
    }

    private void Save(Dictionary<string, Entry> entries)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
            File.WriteAllText(filePath, JsonSerializer.Serialize(entries));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    public void Reset()
    {
        try { File.Delete(filePath); } catch (IOException) { }
    }
}
