using System.Diagnostics;

namespace WinCleaner.Modules.Protection.Rules;

/// <summary>One rule that matched a file.</summary>
public sealed record YaraMatch(string Rule, string File, Dictionary<string, string> Meta)
{
    public Severity Severity => (Meta.GetValueOrDefault("severity") ?? Meta.GetValueOrDefault("level") ?? "").ToLowerInvariant() switch
    {
        "info" or "low" => Severity.Info,
        "warning" or "medium" or "suspicious" => Severity.Warning,
        _ => Severity.Danger,
    };
    public string Description => Meta.GetValueOrDefault("description") ?? Meta.GetValueOrDefault("desc") ?? Rule;
    public string Source => Meta.GetValueOrDefault("author") ?? Meta.GetValueOrDefault("reference") ?? "";
}

/// <summary>
/// Runs the official yara64.exe (the user puts it in the rules folder) over a
/// list of files, with every rule file at once. The output is parsed, never
/// trusted for anything else.
/// </summary>
public static class YaraRunner
{
    /// <summary>Compiles the rules against an empty file: null when fine, the first error otherwise.</summary>
    public static string? Validate(string yara, string rulesFile)
    {
        string probe = Path.Combine(Path.GetTempPath(), "wincleaner-yara-probe-" + Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(probe, []);
        try
        {
            var (exit, output) = Run(yara, ["-w", rulesFile, probe], TimeSpan.FromSeconds(60));
            if (exit == 0) return null;
            return output.Split('\n').FirstOrDefault(l => l.Contains("error", StringComparison.OrdinalIgnoreCase))?.Trim() ?? output.Trim();
        }
        finally { try { File.Delete(probe); } catch (IOException) { } }
    }

    /// <summary>Scans the files with all the rule files; each match is "rule [meta] path".</summary>
    public static List<YaraMatch> Scan(string yara, IReadOnlyList<string> ruleFiles, IReadOnlyList<string> files, TimeSpan? timeout = null)
    {
        if (files.Count == 0 || ruleFiles.Count == 0) return [];
        // The Windows build reads the list as UTF-16 (no BOM), one path per line.
        string list = Path.Combine(Path.GetTempPath(), "wincleaner-yara-list-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(list, string.Concat(files.Select(f => f + "\n")), new System.Text.UnicodeEncoding(false, false));
        try
        {
            var args = new List<string> { "-w", "-m", "--scan-list", "-p", "2" };
            args.AddRange(ruleFiles);
            args.Add(list);
            var (_, output) = Run(yara, args, timeout ?? TimeSpan.FromMinutes(3));
            return Parse(output);
        }
        finally { try { File.Delete(list); } catch (IOException) { } }
    }

    /// <summary>`rule [a="1",b="x y"] C:\path` lines; warnings and errors are skipped.</summary>
    public static List<YaraMatch> Parse(string output)
    {
        var matches = new List<YaraMatch>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith("warning:", StringComparison.OrdinalIgnoreCase) || line.StartsWith("error", StringComparison.OrdinalIgnoreCase)) continue;
            int space = line.IndexOf(' ');
            if (space <= 0) continue;
            string rule = line[..space];
            string rest = line[(space + 1)..];
            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (rest.StartsWith('['))
            {
                int close = rest.IndexOf("] ", StringComparison.Ordinal);
                if (close < 0) continue;
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(rest[1..close], @"(\w+)=(""((?:[^""\\]|\\.)*)""|[^,]+)"))
                    meta[m.Groups[1].Value] = m.Groups[3].Success ? m.Groups[3].Value.Replace("\\\"", "\"") : m.Groups[2].Value;
                rest = rest[(close + 2)..];
            }
            if (rest.Length == 0) continue;
            matches.Add(new YaraMatch(rule, rest, meta));
        }
        return matches;
    }

    private static (int Exit, string Output) Run(string yara, IEnumerable<string> args, TimeSpan timeout)
    {
        var info = new ProcessStartInfo(yara) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) info.ArgumentList.Add(a);
        using var p = Process.Start(info)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeout)) { try { p.Kill(true); } catch (Exception) { } }
        return (p.HasExited ? p.ExitCode : -1, output.Result + error.Result);
    }
}
