using System.Security.Cryptography;
using System.Text.Json;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Rules;

/// <summary>A rule file, hash list, driver list or the YARA binary the user added, with its digest.</summary>
public sealed record RuleFile(string Path, long Size, string Sha256)
{
    public string Name => System.IO.Path.GetFileName(Path);
    public string Kind => System.IO.Path.GetExtension(Path).ToLowerInvariant() switch
    {
        ".yar" or ".yara" => "Regole YARA",
        ".csv" or ".txt" => "Elenco di hash",
        ".json" => "Elenco LOLDrivers",
        ".exe" => "Eseguibile YARA",
        _ => "File",
    };
    public bool IsYaraRules => Kind == "Regole YARA";
    public bool IsHashList => Kind == "Elenco di hash";
    public bool IsDriverList => Kind == "Elenco LOLDrivers";
}

/// <summary>
/// The folder of rule sets, hash lists and the LOLDrivers list. Nothing is
/// downloaded by the app: the user fetches the files from the publisher,
/// adds them here and compares the digest shown with the published one.
/// </summary>
public sealed class RuleStore(string? folder = null)
{
    public string Folder { get; } = folder ?? Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Rules");
    public static readonly string[] Extensions = [".yar", ".yara", ".csv", ".txt", ".json"];

    public List<RuleFile> Files()
    {
        if (!Directory.Exists(Folder)) return [];
        var list = new List<RuleFile>();
        foreach (var file in Directory.EnumerateFiles(Folder))
        {
            string ext = Path.GetExtension(file).ToLowerInvariant();
            if (!Extensions.Contains(ext) && !file.EndsWith("yara64.exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (Path.GetFileName(file).Equals(BundledName, StringComparison.OrdinalIgnoreCase)) continue;
            try { list.Add(new RuleFile(file, new FileInfo(file).Length, Sha256(file))); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return list.OrderBy(f => f.Name).ToList();
    }

    public const string BundledName = "wincleaner-basic.yar";

    /// <summary>The rules shipped with the app, written next to the user's so yara64.exe can read them.</summary>
    public string BundledRules()
    {
        Directory.CreateDirectory(Folder);
        string path = Path.Combine(Folder, BundledName);
        using var stream = typeof(RuleStore).Assembly.GetManifestResourceStream("WinCleaner.Rules." + BundledName);
        if (stream is null) return path;
        using var reader = new StreamReader(stream);
        string text = reader.ReadToEnd();
        if (!File.Exists(path) || File.ReadAllText(path) != text) File.WriteAllText(path, text);
        return path;
    }

    public string? YaraExecutable()
    {
        string path = Path.Combine(Folder, "yara64.exe");
        return File.Exists(path) ? path : null;
    }

    /// <summary>Copies a file in (never moved). Rule files that do not compile are refused when yara64.exe is available.</summary>
    public RuleFile Add(string source)
    {
        var info = new FileInfo(source);
        if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidOperationException("non è un file");
        if (info.Length > 200_000_000) throw new InvalidOperationException("file troppo grande");
        string ext = info.Extension.ToLowerInvariant();
        bool yaraBinary = info.Name.Equals("yara64.exe", StringComparison.OrdinalIgnoreCase);
        if (!Extensions.Contains(ext) && !yaraBinary) throw new InvalidOperationException("tipo di file non previsto (.yar, .csv, .txt, .json o yara64.exe)");
        // The official yara64.exe is not Authenticode-signed: the SHA-256 shown in Settings is what the user compares with the release page.
        Directory.CreateDirectory(Folder);
        string destination = Path.Combine(Folder, info.Name);
        if (ext is ".yar" or ".yara" && YaraExecutable() is { } yara)
        {
            var error = YaraRunner.Validate(yara, source);
            if (error is not null) throw new InvalidOperationException("regole non valide: " + error);
        }
        if (ext == ".json" && LolDrivers.Parse(File.ReadAllText(source)).Count == 0) throw new InvalidOperationException("non sembra l'elenco di LOLDrivers (drivers.json)");
        File.Copy(source, destination, overwrite: true);
        OperationLog.Standard.Write($"rules\tadd\t{destination}");
        return new RuleFile(destination, info.Length, Sha256(destination));
    }

    public void Remove(RuleFile file)
    {
        if (!PathGuard.IsStrictlyInside(file.Path, Folder)) throw new InvalidOperationException("file fuori dalla cartella delle regole");
        File.Delete(file.Path);
        OperationLog.Standard.Write($"rules\tremove\t{file.Path}");
    }

    public static string Sha256(string file)
    {
        using var stream = File.OpenRead(file);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    /// <summary>A digest of every rule, hash and driver file: when it changes, the scan cache is stale.</summary>
    public string Version()
    {
        var parts = Files().Select(f => f.Sha256).ToList();
        try { parts.Add(Sha256(BundledRules())); } catch (IOException) { }
        return Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('|', parts))));
    }
}

/// <summary>SHA-256 hashes of known malware, from MalwareBazaar's CSV export or any text file with one hash per line.</summary>
public static class KnownHashes
{
    public static Dictionary<string, string> Load(IEnumerable<RuleFile> files)
    {
        var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            string text;
            try { text = File.ReadAllText(file.Path); } catch (IOException) { continue; }
            foreach (var (hash, name) in Parse(text, file.Name)) entries.TryAdd(hash, name);
        }
        return entries;
    }

    /// <summary>MalwareBazaar rows: "first_seen","sha256","md5","sha1","reporter","file_name","type","mime","signature",… Plain lines: a 64-hex hash, optionally followed by a name.</summary>
    public static Dictionary<string, string> Parse(string text, string source)
    {
        var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith('"'))
            {
                var fields = line.Split(',').Select(f => f.Trim().Trim('"')).ToArray();
                if (fields.Length > 1 && fields[1].Length == 64)
                    entries[fields[1]] = fields.Length > 8 && fields[8].Length > 0 && fields[8] != "n/a" ? fields[8] : source;
            }
            else
            {
                var m = System.Text.RegularExpressions.Regex.Match(line, @"^([0-9a-fA-F]{64})\b\s*(.*)$");
                if (m.Success) entries[m.Groups[1].Value] = m.Groups[2].Value.Trim().Length > 0 ? m.Groups[2].Value.Trim() : source;
            }
        }
        return entries;
    }
}

/// <summary>The LOLDrivers list (loldrivers.io, drivers.json): vulnerable or malicious kernel drivers by SHA-256.</summary>
public static class LolDrivers
{
    public sealed record Entry(string Sha256, string Filename, string Category, string Description);

    public static Dictionary<string, Entry> Load(IEnumerable<RuleFile> files)
    {
        var entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            string text;
            try { text = File.ReadAllText(file.Path); } catch (IOException) { continue; }
            foreach (var (hash, entry) in Parse(text)) entries.TryAdd(hash, entry);
        }
        return entries;
    }

    public static Dictionary<string, Entry> Parse(string json)
    {
        var entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return entries;
            foreach (var driver in doc.RootElement.EnumerateArray())
            {
                string category = driver.TryGetProperty("Category", out var c) ? c.GetString() ?? "" : "";
                string description = driver.TryGetProperty("Commands", out var cmd) && cmd.TryGetProperty("Description", out var d) ? d.GetString() ?? "" : "";
                if (!driver.TryGetProperty("KnownVulnerableSamples", out var samples) || samples.ValueKind != JsonValueKind.Array) continue;
                foreach (var sample in samples.EnumerateArray())
                {
                    string? sha = sample.TryGetProperty("SHA256", out var s) ? s.GetString() : null;
                    if (string.IsNullOrEmpty(sha) || sha.Length != 64) continue;
                    string filename = sample.TryGetProperty("Filename", out var f) ? f.GetString() ?? "" : "";
                    entries[sha] = new Entry(sha, filename, category, description);
                }
            }
        }
        catch (JsonException) { }
        return entries;
    }
}
