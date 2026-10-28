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
        var updates = Parse(output);
        Core.OperationLog.Standard.Write($"updates\tcheck exit={exit}\t{updates.Count}");
        if (updates.Count == 0 && exit != 0)
        {
            var last = output.Split('\n').Select(StripProgress).Select(l => l.Trim()).LastOrDefault(l => l.Length > 0);
            throw new InvalidOperationException($"winget ha restituito il codice {exit}{(last is null ? "" : ": " + last)}");
        }
        return updates;
    }

    /// <summary>winget's own exit codes (APPINSTALLER_CLI_ERROR_*), as the process returns them.</summary>
    public const int InstallerFailed = unchecked((int)0x8A15010C);
    public const int UpdateNotApplicable = unchecked((int)0x8A15002B);
    public const int NoApplicableInstaller = unchecked((int)0x8A150011);
    public const int MultiplePackagesFound = unchecked((int)0x8A150014);

    /// <summary>
    /// Installs one update silently. Returns null on success, or a sentence for the user.
    /// A newer version that winget found in the Microsoft Store often does not apply to a
    /// program installed from an installer (the Store carries a different package): the
    /// same program is then asked by name from the winget source, where its installer is.
    /// </summary>
    public static async Task<string?> UpgradeAsync(AvailableUpdate update, CancellationToken cancellation)
    {
        var winget = WingetPath() ?? throw new FileNotFoundException("winget non è installato");
        var (exit, lastLine) = await UpgradeOnceAsync(winget, ["--id", update.Id, "--exact"], update.Id, cancellation);
        if (exit == UpdateNotApplicable && update.Source.Equals("msstore", StringComparison.OrdinalIgnoreCase) && update.Name.Length > 0)
            (exit, lastLine) = await UpgradeOnceAsync(winget, ["--name", update.Name, "--source", "winget"], update.Id, cancellation);
        return exit == 0 ? null : Describe(exit, lastLine);
    }

    private static async Task<(int Exit, string? LastLine)> UpgradeOnceAsync(string winget, string[] selection, string id, CancellationToken cancellation)
    {
        var (exit, output) = await RunAsync(winget,
            ["upgrade", .. selection, "--silent", "--disable-interactivity", "--accept-package-agreements", "--accept-source-agreements"],
            cancellation);
        var lastLine = output.Split('\n').Select(StripProgress).Select(l => l.Trim()).LastOrDefault(l => l.Length > 0);
        Core.OperationLog.Standard.Write($"updates\tupgrade exit={exit}\t{id}\t{string.Join(' ', selection)}\t{lastLine}");
        return (exit, lastLine);
    }

    /// <summary>What to tell the user for a failed upgrade: winget's last line is a log path or a code more often than an explanation.</summary>
    public static string Describe(int exit, string? lastLine) => exit switch
    {
        InstallerFailed => "L'installer del programma si è fermato. Se il programma è aperto, chiudilo e riprova; altrimenti aggiornalo dal suo sito.",
        UpdateNotApplicable => "La versione nuova è nel Microsoft Store e non si applica a questa installazione: aggiorna il programma dal Microsoft Store o dal suo sito.",
        NoApplicableInstaller => "Nessun installer adatto a questo PC nella versione nuova.",
        MultiplePackagesFound => "winget trova più programmi con questo nome: aggiornalo dal terminale con «winget upgrade --id …».",
        _ => lastLine is { Length: > 0 } ? lastLine : $"winget ha restituito il codice 0x{exit:X8}",
    };

    /// <summary>
    /// Processes running from the program's install folder: a silent installer cannot replace
    /// an executable that is in use, and it gives up instead of asking (that is what happened
    /// with Ollama: "DeleteFile failed; code 5"). The caller closes them, or skips the update.
    /// </summary>
    public static List<Process> RunningProcesses(AvailableUpdate update, IReadOnlyList<InstalledProgram>? programs = null)
    {
        programs ??= InstalledPrograms.All(includeStore: false);
        var folders = programs
            .Where(p => p.InstallLocation is not null && MatchesProgram(update.Name, p.Name) && !InstalledPrograms.IsSharedFolder(p.InstallLocation))
            .Select(p => p.InstallLocation!)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        var result = new List<Process>();
        foreach (var folder in folders) result.AddRange(InstalledPrograms.ProcessesIn(folder));
        return result.DistinctBy(p => p.Id).ToList();
    }

    /// <summary>
    /// winget prints the installed program's display name, cut to the column width; the
    /// registry has the whole name. A cut name must be a prefix long enough not to be ambiguous.
    /// </summary>
    public static bool MatchesProgram(string wingetName, string programName)
    {
        wingetName = wingetName.Trim();
        programName = programName.Trim();
        if (wingetName.Length == 0) return false;
        if (programName.Equals(wingetName, StringComparison.OrdinalIgnoreCase)) return true;
        return wingetName.Length >= 12 && programName.StartsWith(wingetName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Asks the processes to close, then ends those still alive after <paramref name="grace"/>. Only the user's own processes can be ended this way.</summary>
    public static async Task CloseAsync(IReadOnlyList<Process> processes, TimeSpan grace)
    {
        foreach (var p in processes) { try { p.CloseMainWindow(); } catch (InvalidOperationException) { } }
        var deadline = DateTime.UtcNow + grace;
        while (DateTime.UtcNow < deadline && processes.Any(p => { try { return !p.HasExited; } catch (InvalidOperationException) { return false; } }))
            await Task.Delay(250);
        foreach (var p in processes)
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
    }

    /// <summary>Parses every table of winget's output (header line followed by a line of dashes).</summary>
    public static List<AvailableUpdate> Parse(string output)
    {
        var lines = output.Split('\n').Select(StripProgress).ToList();
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

    /// <summary>
    /// What a console would show for one line: winget redraws its spinner and
    /// progress bar with carriage returns and backspaces, so only the text
    /// after the last one is kept (a trailing \r from \r\n is ignored).
    /// </summary>
    internal static string StripProgress(string line)
    {
        line = line.TrimEnd('\r');
        int cut = Math.Max(line.LastIndexOf('\r'), line.LastIndexOf('\b'));
        if (cut >= 0) line = line[(cut + 1)..];
        // Escape sequences (colours, cursor moves) some versions print even when redirected.
        return System.Text.RegularExpressions.Regex.Replace(line, @"\x1B\[[0-9;?]*[A-Za-z]", "");
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
        Core.ProcessEnvironment.Sanitize(info, restrictPath: false);
        using var p = Process.Start(info)!;
        var stdout = p.StandardOutput.ReadToEndAsync(cancellation);
        var stderr = p.StandardError.ReadToEndAsync(cancellation);
        await p.WaitForExitAsync(cancellation);
        return (p.ExitCode, await stdout + await stderr);
    }
}
