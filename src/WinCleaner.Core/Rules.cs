using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinCleaner.Core;

public enum RuleTarget
{
    /// <summary>Each item inside the matched folders becomes a result.</summary>
    Children,
    /// <summary>The matched path itself becomes a result.</summary>
    Itself,
}

/// <summary>
/// One cleaning rule, loaded from JSON. Paths start with a token such as
/// <c>%LOCALAPPDATA%</c> and may use * and ? in any later component, for
/// example <c>%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache</c>.
/// </summary>
public sealed record CleaningRule
{
    public required string Id { get; init; }
    /// <summary>Section of the screen: windows, browsers, apps, developer.</summary>
    public string Group { get; init; } = "windows";
    public required string Category { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public required string[] Paths { get; init; }
    public RuleTarget Target { get; init; } = RuleTarget.Children;
    /// <summary>When set, only names matching one of these patterns are returned.</summary>
    public string[] Include { get; init; } = [];
    /// <summary>Names (wildcards allowed) that are never returned.</summary>
    public string[] Excludes { get; init; } = [];
    /// <summary>Only items with nothing inside changed in the last N hours.</summary>
    public double? MinAgeHours { get; init; }
    public RiskLevel Risk { get; init; } = RiskLevel.Low;
    public bool AutoSelect { get; init; } = true;
    /// <summary>Removal needs administrator rights (system folders).</summary>
    public bool Admin { get; init; }
    /// <summary>Process names (without .exe): the rule is skipped while any of them runs.</summary>
    public string[] Processes { get; init; } = [];
    /// <summary>The matched path's parent must contain at least one of these names.</summary>
    public string[] RequireAnySibling { get; init; } = [];
}

public sealed record RuleSet
{
    public int Version { get; init; } = 1;
    /// <summary>Names excluded by every rule of the set.</summary>
    public string[] GlobalExcludes { get; init; } = [];
    public required CleaningRule[] Rules { get; init; }

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static RuleSet Parse(string json) =>
        JsonSerializer.Deserialize<RuleSet>(json, JsonOptions) ?? throw new InvalidDataException("Empty rule set");

    public static RuleSet Load(Stream stream) =>
        JsonSerializer.Deserialize<RuleSet>(stream, JsonOptions) ?? throw new InvalidDataException("Empty rule set");
}

/// <summary>Turns rules into scan results.</summary>
public sealed class RuleEngine
{
    private readonly Func<string, string?> _expand;
    private readonly DateTime _now;
    private readonly HashSet<string> _running;

    /// <param name="expand">Token expansion (defaults to <see cref="KnownPaths.Expand"/>); tests pass their own.</param>
    /// <param name="runningProcesses">Lower-case process names without .exe.</param>
    public RuleEngine(Func<string, string?>? expand = null, IEnumerable<string>? runningProcesses = null, DateTime? now = null)
    {
        _expand = expand ?? KnownPaths.Expand;
        _running = new HashSet<string>(runningProcesses ?? RunningProcessNames(), StringComparer.OrdinalIgnoreCase);
        _now = now ?? DateTime.UtcNow;
    }

    public static HashSet<string> RunningProcessNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try { names.Add(p.ProcessName); } catch (InvalidOperationException) { }
            p.Dispose();
        }
        return names;
    }

    public sealed record Output(IReadOnlyList<ScanCategory> Categories, IReadOnlyList<string> Notes, IReadOnlyList<string> Unreadable);

    public Output Evaluate(RuleSet set, CancellationToken cancellation = default)
    {
        var byCategory = new Dictionary<string, (CleaningRule First, List<ScanItem> Items)>();
        var order = new List<string>();
        var notes = new List<string>();
        var unreadable = new List<string>();

        foreach (var rule in set.Rules)
        {
            cancellation.ThrowIfCancellationRequested();
            var runningOwner = rule.Processes.FirstOrDefault(_running.Contains);
            if (runningOwner is not null)
            {
                notes.Add($"{rule.Title}: saltato perché {runningOwner}.exe è aperto");
                continue;
            }

            var excludes = set.GlobalExcludes.Concat(rule.Excludes).ToArray();
            var items = new List<ScanItem>();
            foreach (var pattern in rule.Paths)
            {
                foreach (var match in Expand(pattern))
                {
                    if (rule.RequireAnySibling.Length > 0 && !HasSibling(match, rule.RequireAnySibling)) continue;
                    if (rule.Target == RuleTarget.Itself)
                    {
                        if (MakeItem(match, rule, excludes, cancellation) is { } item) items.Add(item);
                        continue;
                    }
                    if (!Directory.Exists(match)) continue;
                    try
                    {
                        foreach (var child in FileWalker.Children(match))
                        {
                            if (MakeItem(child.Path, rule, excludes, cancellation) is { } item) items.Add(item);
                        }
                    }
                    catch (UnauthorizedAccessException) { unreadable.Add(match); }
                    catch (IOException) { unreadable.Add(match); }
                }
            }
            items.RemoveAll(i => i.Size <= 0);
            if (items.Count == 0) continue;
            if (!byCategory.TryGetValue(rule.Category, out var entry))
            {
                order.Add(rule.Category);
                entry = (rule, []);
                byCategory[rule.Category] = entry;
            }
            entry.Items.AddRange(items);
        }

        // Rules can overlap (a folder and something inside it). Keep only the
        // outermost item, and only its first occurrence, so sizes are not
        // counted twice and nothing is removed twice.
        var allPaths = new HashSet<string>(byCategory.Values.SelectMany(v => v.Items.Select(i => i.Path)), StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var categories = new List<ScanCategory>();
        foreach (var key in order)
        {
            var (first, items) = byCategory[key];
            var kept = items.Where(i => !HasAncestor(i.Path, allPaths) && seen.Add(i.Path))
                .OrderByDescending(i => i.Size).ToList();
            if (kept.Count == 0) continue;
            categories.Add(new ScanCategory(key, first.Title, kept) { Description = first.Description, Group = first.Group });
        }
        return new Output(categories, notes, unreadable);
    }

    internal static bool HasAncestor(string path, HashSet<string> paths)
    {
        string? current = Path.GetDirectoryName(path);
        while (!string.IsNullOrEmpty(current) && current.Length > 3)
        {
            if (paths.Contains(current)) return true;
            current = Path.GetDirectoryName(current);
        }
        return false;
    }

    private static bool HasSibling(string path, string[] names)
    {
        string? parent = Path.GetDirectoryName(path);
        return parent is not null && names.Any(n => Path.Exists(Path.Combine(parent, n)));
    }

    private ScanItem? MakeItem(string path, CleaningRule rule, string[] excludes, CancellationToken cancellation)
    {
        string name = Path.GetFileName(path);
        if (rule.Include.Length > 0 && !rule.Include.Any(p => FileWalker.Matches(name, p))) return null;
        if (excludes.Any(p => FileWalker.Matches(name, p))) return null;
        TreeSize size;
        try { size = FileWalker.Measure(path, cancellation); }
        catch (UnauthorizedAccessException) { return null; }
        catch (IOException) { return null; }
        if (rule.MinAgeHours is { } hours && (_now - size.NewestWriteUtc).TotalHours < hours) return null;
        return new ScanItem(path, size.Bytes, rule.Risk, rule.AutoSelect, rule.Admin, LastWriteUtc: size.NewestWriteUtc);
    }

    /// <summary>
    /// Expands the leading token and the wildcards into the existing paths that
    /// match. Junctions and symbolic links below the token are not followed.
    /// </summary>
    public IEnumerable<string> Expand(string pattern)
    {
        int split = pattern.IndexOf('\\', pattern.StartsWith('%') ? pattern.IndexOf('%', 1) + 1 : 3);
        string head = split < 0 ? pattern : pattern[..split];
        string? basePath = _expand(head);
        if (basePath is null || !PathGuard.IsValidPath(basePath) || !Directory.Exists(basePath)) yield break;
        if (split < 0) { yield return basePath; yield break; }

        var current = new List<string> { basePath };
        foreach (var component in pattern[(split + 1)..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            var next = new List<string>();
            foreach (var folder in current)
            {
                if (FileWalker.HasWildcard(component))
                {
                    IEnumerable<(string Path, FileAttributes Attributes, long, DateTime)> children;
                    try { children = FileWalker.Children(folder).ToList(); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    foreach (var child in children)
                    {
                        if ((child.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if (FileWalker.Matches(Path.GetFileName(child.Path), component)) next.Add(child.Path);
                    }
                }
                else
                {
                    string candidate = Path.Combine(folder, component);
                    try
                    {
                        var attributes = File.GetAttributes(candidate);
                        if ((attributes & FileAttributes.ReparsePoint) == 0) next.Add(candidate);
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            current = next;
            if (current.Count == 0) yield break;
        }
        foreach (var path in current) yield return path;
    }
}
