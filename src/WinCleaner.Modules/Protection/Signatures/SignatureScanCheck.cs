using System.Security.Cryptography;
using System.Text.Json;
using WinCleaner.Core;
using WinCleaner.Modules.Protection.Rules;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>Which files are worth a signature scan: executables and scripts in the places malware lives, never the whole disk.</summary>
public static class ScanTargets
{
    public const long MaximumFileSize = 50_000_000;
    public const int MaximumFiles = 3000;
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".py", ".jar", ".scr", ".pif", ".com", ".sys", ".dll", ".exe", ".msi", ".lnk" };

    /// <summary>Folders scanned a few levels deep, plus the programs the start-up items, services and drivers run.</summary>
    public static List<string> Candidates(CheckContext context, IEnumerable<string>? extraFolders = null, bool onlyExtra = false)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = new List<string>();
        void Add(string path)
        {
            if (files.Count >= MaximumFiles) return;
            try { path = KnownPaths.Long(path); } catch (Exception) { return; }
            if (seen.Add(path) && IsScannable(path)) files.Add(path);
        }
        var folders = new List<(string Folder, int Depth)>();
        if (!onlyExtra)
        {
            foreach (var item in context.Startup) if (item.Executable is { } exe) Add(exe);
            string profile = context.UserProfile;
            folders.AddRange(
            [
                (Path.Combine(profile, "Downloads"), 2), (Path.Combine(profile, "Desktop"), 1), (Path.Combine(profile, "Documents"), 1),
                (Path.Combine(profile, "AppData", "Roaming"), 2), (Path.Combine(profile, "AppData", "Local"), 2), (Path.Combine(profile, "AppData", "Local", "Temp"), 2),
                (KnownPaths.ProgramData, 2), (KnownPaths.Public, 3), (KnownPaths.Startup, 1), (KnownPaths.CommonStartup, 1),
                (Path.Combine(KnownPaths.Windows, "Temp"), 2), (Path.Combine(KnownPaths.Windows, "Tasks"), 1), (Path.Combine(KnownPaths.Windows, "System32", "Tasks"), 2),
                (Path.Combine(KnownPaths.SystemDrive, "Users", "Public"), 3), (Path.Combine(KnownPaths.SystemDrive, "Temp"), 2), (Path.Combine(KnownPaths.SystemDrive, "Intel"), 2),
                (Path.Combine(KnownPaths.SystemDrive, "PerfLogs"), 2), (Path.Combine(KnownPaths.SystemDrive, "Tools"), 2),
            ]);
        }
        foreach (var extra in extraFolders ?? []) folders.Add((extra, 3));
        foreach (var (folder, depth) in folders) Walk(folder, depth, Add);
        return files;
    }

    /// <summary>Lists files a few levels deep, never through reparse points, skipping the Microsoft folders under AppData.</summary>
    public static void Walk(string folder, int depth, Action<string> add)
    {
        if (depth < 0) return;
        IEnumerable<string> entries;
        try { entries = Directory.EnumerateFileSystemEntries(folder); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return; }
        int count = 0;
        foreach (var entry in entries)
        {
            if (++count > 2000) break;
            FileAttributes attributes;
            try { attributes = File.GetAttributes(entry); } catch (Exception) { continue; }
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
            // OneDrive placeholders: reading them would download them.
            if ((attributes & (FileAttributes)0x400000) != 0 || (attributes & FileAttributes.Offline) != 0) continue;
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                string name = Path.GetFileName(entry);
                if (name.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) && entry.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.Equals("Packages", StringComparison.OrdinalIgnoreCase) || name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) || name.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase)) continue;
                Walk(entry, depth - 1, add);
            }
            else add(entry);
        }
    }

    /// <summary>PE ("MZ"), a script extension, a shortcut; small enough to scan.</summary>
    public static bool IsScannable(string path)
    {
        FileInfo info;
        try { info = new FileInfo(path); } catch (Exception) { return false; }
        if (!info.Exists || info.Length == 0 || info.Length > MaximumFileSize) return false;
        if (ScriptExtensions.Contains(info.Extension)) return true;
        try
        {
            using var stream = info.OpenRead();
            Span<byte> head = stackalloc byte[2];
            return stream.Read(head) == 2 && head[0] == 0x4D && head[1] == 0x5A;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}

/// <summary>Remembers the verdict for each file (by path, size and date) so a rescan with the same rules only reads what changed.</summary>
public sealed class ScanCache(string? filePath = null)
{
    public sealed record Entry(long Size, long Modified, string? Sha256, List<string> Matches);
    private sealed record Contents(string RulesVersion, Dictionary<string, Entry> Entries);
    public string FilePath { get; } = filePath ?? Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Protection", "signature-cache.json");

    public Dictionary<string, Entry> Load(string rulesVersion)
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var contents = JsonSerializer.Deserialize<Contents>(File.ReadAllText(FilePath));
                if (contents?.RulesVersion == rulesVersion) return new Dictionary<string, Entry>(contents.Entries, StringComparer.OrdinalIgnoreCase);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        return new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
    }

    public void Save(Dictionary<string, Entry> entries, string rulesVersion)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(new Contents(rulesVersion, entries)));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>
/// Known hashes (MalwareBazaar), vulnerable drivers (LOLDrivers) and YARA
/// rules over the files that matter. Defender stays the antivirus: this is a
/// second opinion with the quarantine as its action.
/// </summary>
public sealed class SignatureScanCheck(RuleStore? store = null, ScanCache? cache = null, IEnumerable<string>? extraFolders = null, bool onlyExtra = false) : IProtectionCheck
{
    public string Id => "signatures";
    public string Title => "Firme conosciute";
    private readonly RuleStore _store = store ?? new RuleStore();
    private readonly ScanCache? _cache = cache ?? new ScanCache();

    /// <summary>The pins to check the files against; tests pass their own, the app reads ProgramData\WinCleaner\Pins.</summary>
    public IReadOnlyDictionary<string, string>? Pins { get; init; } = RulePins.Load();

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var all = _store.Files();
        if (all.Count == 0) yield break;
        // Files that changed after the user confirmed them (or were never confirmed) come from a folder any program
        // with the user's rights can write: a changed yara64.exe is never run, a changed rule file is skipped.
        var files = new List<RuleFile>();
        bool unconfirmed = false;
        foreach (var file in all)
        {
            switch (RulePins.Check(Pins, file))
            {
                case RulePins.Verdict.Confirmed: files.Add(file); break;
                case RulePins.Verdict.Changed:
                    yield return new Finding($"rules-changed|{file.Name}", Categories.Signatures, $"{file.Name} è cambiato dopo la conferma",
                        file.Name.Equals("yara64.exe", StringComparison.OrdinalIgnoreCase)
                            ? "L'eseguibile YARA nella cartella delle regole non è più quello confermato come amministratore: non viene eseguito. Se l'hai aggiornato tu, confermalo di nuovo dalle Impostazioni; altrimenti qualcosa lo ha sostituito."
                            : "Il file delle regole non è più quello confermato: viene ignorato finché non lo confermi di nuovo dalle Impostazioni.",
                        file.Name.Equals("yara64.exe", StringComparison.OrdinalIgnoreCase) ? Severity.Danger : Severity.Warning)
                    { Path = file.Path, Evidence = [$"SHA-256 attuale: {file.Sha256}", $"SHA-256 confermato: {Pins?.GetValueOrDefault(file.Name) ?? "?"}"] };
                    break;
                default:
                    unconfirmed = true;
                    if (!file.Name.Equals("yara64.exe", StringComparison.OrdinalIgnoreCase)) files.Add(file);
                    break;
            }
        }
        if (unconfirmed)
            yield return new Finding("rules-unconfirmed", Categories.Signatures, "File delle firme non confermati",
                "Regole o yara64.exe aggiunti ma non confermati come amministratore: un programma con i tuoi diritti potrebbe cambiarli. yara64.exe non viene eseguito finché non lo confermi dalle Impostazioni.", Severity.Warning)
            { Path = _store.Folder };
        var hashes = KnownHashes.Load(files.Where(f => f.IsHashList));
        var drivers = LolDrivers.Load(files.Where(f => f.IsDriverList));
        string? yara = files.Any(f => f.Name.Equals("yara64.exe", StringComparison.OrdinalIgnoreCase)) ? _store.YaraExecutable() : null;
        var ruleFiles = yara is null ? [] : new List<string> { _store.BundledRules() }.Concat(files.Where(f => f.IsYaraRules).Select(f => f.Path)).ToList();
        if (hashes.Count == 0 && drivers.Count == 0 && yara is null) yield break;

        string version = _store.Version() + "|" + (yara is null ? "" : RuleStore.Sha256(yara));
        var entries = _cache?.Load(version) ?? new Dictionary<string, ScanCache.Entry>(StringComparer.OrdinalIgnoreCase);
        var candidates = ScanTargets.Candidates(context, extraFolders, onlyExtra);
        if (drivers.Count > 0 && !onlyExtra)
        {
            string driversFolder = Path.Combine(KnownPaths.Windows, "System32", "drivers");
            try { foreach (var sys in Directory.EnumerateFiles(driversFolder, "*.sys")) candidates.Add(sys); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        var deadline = DateTime.UtcNow.AddSeconds(150);

        // Hashes first (cheap), then one YARA run over everything not cached.
        var fresh = new List<string>();
        foreach (var path in candidates)
        {
            if (DateTime.UtcNow > deadline) break;
            FileInfo info;
            try { info = new FileInfo(path); if (!info.Exists) continue; } catch (Exception) { continue; }
            long modified = info.LastWriteTimeUtc.Ticks;
            if (entries.TryGetValue(path, out var cached) && cached.Size == info.Length && cached.Modified == modified) continue;
            string? sha = null;
            if (hashes.Count > 0 || drivers.Count > 0)
            {
                try { using var stream = info.OpenRead(); sha = Convert.ToHexStringLower(SHA256.HashData(stream)); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
            entries[path] = new ScanCache.Entry(info.Length, modified, sha, []);
            fresh.Add(path);
        }
        if (yara is not null && fresh.Count > 0 && DateTime.UtcNow < deadline)
        {
            List<YaraMatch> matches;
            try { matches = YaraRunner.Scan(yara, ruleFiles, fresh); }
            catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException) { matches = []; }
            foreach (var match in matches)
            {
                if (!entries.TryGetValue(match.File, out var entry)) continue;
                entry.Matches.Add($"{match.Rule}|{(int)match.Severity}|{match.Description}|{match.Source}");
            }
        }
        _cache?.Save(entries, version);

        foreach (var (path, entry) in entries)
        {
            if (!candidates.Contains(path, StringComparer.OrdinalIgnoreCase)) continue;
            foreach (var match in entry.Matches)
            {
                var parts = match.Split('|', 4);
                var severity = parts.Length > 1 && int.TryParse(parts[1], out var s) ? (Severity)s : Severity.Danger;
                yield return new Finding($"yara|{path}|{parts[0]}", Categories.Signatures, $"{Path.GetFileName(path)}: {parts[0]}",
                    (parts.Length > 2 && parts[2].Length > 0 ? parts[2] : "Corrisponde a una regola YARA") + ".", severity)
                { Path = path, Evidence = [$"Regola: {parts[0]}", $"Fonte: {(parts.Length > 3 ? parts[3] : "?")}"], Action = FindingAction.Quarantine };
            }
            if (entry.Sha256 is { } sha)
            {
                if (hashes.TryGetValue(sha, out var name))
                    yield return new Finding($"hash|{path}", Categories.Signatures, $"{Path.GetFileName(path)}: malware conosciuto",
                        $"Il file ha lo stesso SHA-256 di un campione segnalato come {name}.", Severity.Danger)
                    { Path = path, Evidence = [$"SHA-256: {sha}"], Action = FindingAction.Quarantine };
                if (drivers.TryGetValue(sha, out var driver))
                    yield return new Finding($"loldriver|{path}", Categories.Signatures, $"Driver vulnerabile o malevolo: {Path.GetFileName(path)}",
                        $"È nell'elenco LOLDrivers ({driver.Category}): gli attaccanti lo caricano per spegnere Defender o leggere la memoria. {driver.Description}".Trim(), Severity.Danger)
                    { Path = path, Evidence = [$"SHA-256: {sha}", $"Nome noto: {driver.Filename}"], Action = FindingAction.DefenderScan };
            }
        }
    }
}
