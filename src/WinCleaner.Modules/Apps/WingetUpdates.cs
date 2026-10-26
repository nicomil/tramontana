using System.Diagnostics;
using System.Text;

namespace WinCleaner.Modules.Apps;

/// <summary>An update offered by the Windows Package Manager.</summary>
public sealed record AvailableUpdate(string Name, string Id, string InstalledVersion, string AvailableVersion, string Source);

/// <summary>
/// Updates through winget (App Installer), the package manager that ships
/// with Windows: it checks publisher hashes before installing. The table
/// printed by "winget upgrade" is read by column position, so it works in any
/// display language.
/// </summary>
public static class WingetUpdates
{
    public static string? WingetPath()
    {
        string local = Path.Combine(Core.KnownPaths.LocalAppData, "Microsoft", "WindowsApps", "winget.exe");
        if (File.Exists(local)) return local;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), "winget.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    public static async Task<IReadOnlyList<AvailableUpdate>> CheckAsync(CancellationToken cancellation)
    {
        var winget = WingetPath() ?? throw new FileNotFoundException("winget non è installato (App Installer da Microsoft Store)");
        var (exit, output) = await RunAsync(winget, ["upgrade", "--include-unknown", "--disable-interactivity", "--accept-source-agreements"], cancellation);
        return Parse(output);
    }

    /// <summary>Installs one update silently. Returns null on success, or the error text.</summary>
    public static async Task<string?> UpgradeAsync(string id, CancellationToken cancellation)
    {
        var winget = WingetPath() ?? throw new FileNotFoundException("winget non è installato");
        var (exit, output) = await RunAsync(winget,
            ["upgrade", "--id", id, "--exact", "--silent", "--disable-interactivity", "--accept-package-agreements", "--accept-source-agreements"],
            cancellation);
        if (exit == 0) return null;
        var last = output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0);
        return last ?? $"winget ha restituito il codice {exit}";
    }

    /// <summary>Parses every table of winget's output (header line followed by a line of dashes).</summary>
    public static List<AvailableUpdate> Parse(string output)
    {
        var lines = output.Replace("\r", "").Split('\n').Select(StripProgress).ToList();
        var result = new List<AvailableUpdate>();
        for (int i = 1; i < lines.Count; i++)
        {
            if (lines[i].Length < 10 || lines[i].Trim().Any(c => c != '-')) continue;
            string header = lines[i - 1];
            var starts = ColumnStarts(header);
            if (starts.Count < 4) continue;
            for (int j = i + 1; j < lines.Count; j++)
            {
                string row = lines[j];
                if (row.Trim().Length == 0) break;
                if (row.Length < starts[^1] - 1 || (j + 1 < lines.Count && lines[j + 1].Trim().All(c => c == '-') && lines[j + 1].Length > 10)) break;
                string Cell(int k) => Slice(row, starts[k], k + 1 < starts.Count ? starts[k + 1] : row.Length);
                var update = new AvailableUpdate(Cell(0), Cell(1), Cell(2), Cell(3), starts.Count > 4 ? Cell(4) : "");
                if (update.Id.Length > 0 && !update.Id.Contains(' ') && update.AvailableVersion.Length > 0) result.Add(update);
            }
        }
        return result;
    }

    private static List<int> ColumnStarts(string header)
    {
        var starts = new List<int>();
        for (int k = 0; k < header.Length; k++)
            if (header[k] != ' ' && (k == 0 || header[k - 1] == ' ')) starts.Add(k);
        return starts;
    }

    private static string Slice(string row, int start, int end)
    {
        if (start >= row.Length) return "";
        end = Math.Min(end, row.Length);
        return row[start..end].Trim().TrimEnd('…');
    }

    /// <summary>Drops the spinner and progress bar that winget prints before the table.</summary>
    private static string StripProgress(string line)
    {
        int cut = line.LastIndexOf('\b');
        return cut >= 0 ? line[(cut + 1)..] : line;
    }

    private static async Task<(int Exit, string Output)> RunAsync(string file, string[] args, CancellationToken cancellation)
    {
        var info = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        foreach (var a in args) info.ArgumentList.Add(a);
        using var p = Process.Start(info)!;
        var stdout = p.StandardOutput.ReadToEndAsync(cancellation);
        var stderr = p.StandardError.ReadToEndAsync(cancellation);
        await p.WaitForExitAsync(cancellation);
        return (p.ExitCode, await stdout + await stderr);
    }
}
