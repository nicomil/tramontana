using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Performance;

namespace WinCleaner.Modules.Protection;

/// <summary>What a check needs before it can see anything.</summary>
public enum CheckRequirement
{
    None,
    /// <summary>Reads the output of the helper's read-only evidence collection.</summary>
    Admin,
}

/// <summary>One unit of the Protection scan.</summary>
public interface IProtectionCheck
{
    string Id { get; }
    string Title { get; }
    CheckRequirement Requirement => CheckRequirement.None;
    IEnumerable<Finding> Run(CheckContext context);
}

/// <summary>Reads the registry. Injected so tests can feed fixed values.</summary>
public interface IRegistryReader
{
    object? GetValue(string keyPath, string valueName);
    string[] SubKeys(string keyPath);
    string[] ValueNames(string keyPath);
    bool KeyExists(string keyPath);
}

public static class RegistryReaderExtensions
{
    public static string? GetString(this IRegistryReader r, string key, string value) => r.GetValue(key, value) as string;
    public static int? GetInt(this IRegistryReader r, string key, string value) => r.GetValue(key, value) is int i ? i : null;
    public static string[] GetStrings(this IRegistryReader r, string key, string value) => r.GetValue(key, value) as string[] ?? [];
}

/// <summary>The real registry, read-only, 64-bit view, every hive.</summary>
public sealed class RegistryReader : IRegistryReader
{
    public static RegistryKey? Open(string keyPath)
    {
        var path = keyPath.Trim().TrimEnd('\\');
        int slash = path.IndexOf('\\');
        string hive = (slash < 0 ? path : path[..slash]).ToUpperInvariant();
        string rest = slash < 0 ? "" : path[(slash + 1)..];
        RegistryHive? h = hive switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            _ => null,
        };
        if (h is null) return null;
        try
        {
            var root = RegistryKey.OpenBaseKey(h.Value, RegistryView.Registry64);
            if (rest.Length == 0) return root;
            var key = root.OpenSubKey(rest, writable: false);
            root.Dispose();
            return key;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    public object? GetValue(string keyPath, string valueName)
    {
        using var key = Open(keyPath);
        try { return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    public string[] SubKeys(string keyPath)
    {
        using var key = Open(keyPath);
        try { return key?.GetSubKeyNames() ?? []; }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return []; }
    }

    public string[] ValueNames(string keyPath)
    {
        using var key = Open(keyPath);
        try { return key?.GetValueNames() ?? []; }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return []; }
    }

    public bool KeyExists(string keyPath)
    {
        using var key = Open(keyPath);
        return key is not null;
    }
}

/// <summary>Fixed registry contents for tests: "HKEY_…\Key" → value name → value. Hive names are normalized.</summary>
public sealed class FakeRegistry : IRegistryReader
{
    private readonly Dictionary<string, Dictionary<string, object?>> _keys = new(StringComparer.OrdinalIgnoreCase);

    public FakeRegistry Set(string keyPath, string valueName, object? value)
    {
        var key = Normalize(keyPath);
        if (!_keys.TryGetValue(key, out var values)) _keys[key] = values = new(StringComparer.OrdinalIgnoreCase);
        values[valueName] = value;
        // Parent keys exist too.
        for (int i = key.LastIndexOf('\\'); i > 0; i = key.LastIndexOf('\\', i - 1))
            _keys.TryAdd(key[..i], new(StringComparer.OrdinalIgnoreCase));
        return this;
    }

    public FakeRegistry Key(string keyPath)
    {
        var key = Normalize(keyPath);
        _keys.TryAdd(key, new(StringComparer.OrdinalIgnoreCase));
        for (int i = key.LastIndexOf('\\'); i > 0; i = key.LastIndexOf('\\', i - 1))
            _keys.TryAdd(key[..i], new(StringComparer.OrdinalIgnoreCase));
        return this;
    }

    private static string Normalize(string keyPath)
    {
        var path = keyPath.Trim().TrimEnd('\\');
        int slash = path.IndexOf('\\');
        string hive = (slash < 0 ? path : path[..slash]).ToUpperInvariant() switch
        {
            "HKCU" => "HKEY_CURRENT_USER", "HKLM" => "HKEY_LOCAL_MACHINE", "HKCR" => "HKEY_CLASSES_ROOT", "HKU" => "HKEY_USERS",
            var other => other,
        };
        return slash < 0 ? hive : hive + path[slash..];
    }

    public object? GetValue(string keyPath, string valueName) =>
        _keys.TryGetValue(Normalize(keyPath), out var values) && values.TryGetValue(valueName, out var v) ? v : null;

    public string[] SubKeys(string keyPath)
    {
        var prefix = Normalize(keyPath) + "\\";
        return [.. _keys.Keys.Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !k[prefix.Length..].Contains('\\'))
            .Select(k => k[prefix.Length..]).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    public string[] ValueNames(string keyPath) => _keys.TryGetValue(Normalize(keyPath), out var values) ? [.. values.Keys] : [];
    public bool KeyExists(string keyPath) => _keys.ContainsKey(Normalize(keyPath));
}

/// <summary>Runs external tools. Injected so tests can feed canned output to the parsers.</summary>
public interface ICommandRunner
{
    /// <summary>Standard output (and error) of the tool, or "" when it cannot run.</summary>
    string Run(string file, params string[] args);
}

public sealed class SystemCommands : ICommandRunner
{
    public string Run(string file, params string[] args)
    {
        try
        {
            string path = Path.IsPathRooted(file) ? file : Path.Combine(Environment.SystemDirectory, file);
            if (file.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
                path = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(path)) return "";
            var info = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in args) info.ArgumentList.Add(a);
            ProcessEnvironment.Sanitize(info);
            using var p = Process.Start(info)!;
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(60_000)) { try { p.Kill(true); } catch (Exception) { } }
            return output.Result + error.Result;
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException) { return ""; }
    }
}

/// <summary>Canned output for tests: keyed by "file arg1 arg2".</summary>
public sealed class FakeCommands(Dictionary<string, string>? outputs = null) : ICommandRunner
{
    public Dictionary<string, string> Outputs { get; } = outputs ?? new(StringComparer.OrdinalIgnoreCase);
    public string Run(string file, params string[] args) =>
        Outputs.TryGetValue(string.Join(' ', [file, .. args]), out var output) ? output : "";
}

public interface ISignatureEvaluator
{
    SignatureInfo Check(string path);
}

public sealed class SystemSignatures : ISignatureEvaluator
{
    public SignatureInfo Check(string path) => Signatures.Check(path);
}

/// <summary>Fixed verdicts for tests, by path; anything else is Microsoft-signed.</summary>
public sealed class FakeSignatures(SignatureInfo? fallback = null) : ISignatureEvaluator
{
    public Dictionary<string, SignatureInfo> Verdicts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public SignatureInfo Fallback { get; } = fallback ?? new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows");
    public FakeSignatures With(string path, SignatureStatus status, string? publisher = null) { Verdicts[path] = new SignatureInfo(status, publisher); return this; }
    public SignatureInfo Check(string path) => Verdicts.TryGetValue(path, out var v) ? v : Fallback;
}

/// <summary>WMI queries as rows of name → value.</summary>
public interface IWmiSource
{
    IReadOnlyList<Dictionary<string, object?>> Query(string scope, string wql);
}

public sealed class SystemWmi : IWmiSource
{
    public IReadOnlyList<Dictionary<string, object?>> Query(string scope, string wql)
    {
        var rows = new List<Dictionary<string, object?>>();
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, wql);
            foreach (ManagementObject o in searcher.Get())
            {
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in o.Properties) row[p.Name] = p.Value;
                rows.Add(row);
            }
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException or InvalidOperationException) { }
        return rows;
    }
}

/// <summary>Canned WMI rows for tests, keyed by "scope|wql".</summary>
public sealed class FakeWmi : IWmiSource
{
    public Dictionary<string, List<Dictionary<string, object?>>> Rows { get; } = new(StringComparer.OrdinalIgnoreCase);
    public FakeWmi Add(string scope, string wql, params Dictionary<string, object?>[] rows)
    {
        if (!Rows.TryGetValue(scope + "|" + wql, out var list)) Rows[scope + "|" + wql] = list = [];
        list.AddRange(rows);
        return this;
    }
    public IReadOnlyList<Dictionary<string, object?>> Query(string scope, string wql) =>
        Rows.TryGetValue(scope + "|" + wql, out var rows) ? rows : [];
}

/// <summary>A certificate in one of the root stores.</summary>
public sealed record RootCertificate(string Store, string Subject, string Issuer, DateTime NotBefore, string Thumbprint)
{
    public bool IsSelfSigned => string.Equals(Subject, Issuer, StringComparison.OrdinalIgnoreCase);
}

public interface ICertificateSource
{
    IReadOnlyList<RootCertificate> Roots();
}

public sealed class SystemCertificates : ICertificateSource
{
    public IReadOnlyList<RootCertificate> Roots()
    {
        var list = new List<RootCertificate>();
        foreach (var (location, name) in new[] { (System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, "utente"), (System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, "computer") })
        {
            try
            {
                using var store = new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.Root, location);
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly | System.Security.Cryptography.X509Certificates.OpenFlags.OpenExistingOnly);
                foreach (var cert in store.Certificates)
                    list.Add(new RootCertificate(name, cert.Subject, cert.Issuer, cert.NotBefore, cert.Thumbprint));
            }
            catch (System.Security.Cryptography.CryptographicException) { }
        }
        return list;
    }
}

public sealed class FakeCertificates(params RootCertificate[] roots) : ICertificateSource
{
    public IReadOnlyList<RootCertificate> Roots() => roots;
}

/// <summary>Output of the helper's read-only evidence collection, split by section.</summary>
public sealed class SystemEvidence
{
    public Dictionary<string, string> Sections { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? this[string name] => Sections.TryGetValue(name, out var s) ? s : null;

    /// <summary>Splits text on "### name" headers.</summary>
    public static SystemEvidence Parse(string text)
    {
        var evidence = new SystemEvidence();
        string? current = null;
        var lines = new List<string>();
        void Flush() { if (current is not null) evidence.Sections[current] = string.Join('\n', lines); }
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("### ", StringComparison.Ordinal)) { Flush(); current = line[4..].Trim(); lines.Clear(); }
            else lines.Add(line);
        }
        Flush();
        return evidence;
    }
}

/// <summary>Everything a check may need, built once per scan.</summary>
public sealed class CheckContext
{
    public IRegistryReader Registry { get; init; } = new RegistryReader();
    public ICommandRunner Commands { get; init; } = new SystemCommands();
    public ISignatureEvaluator Signatures { get; init; } = new SystemSignatures();
    public IWmiSource Wmi { get; init; } = new SystemWmi();
    public DateTime Now { get; init; } = DateTime.Now;
    public SystemEvidence? Evidence { get; init; }
    /// <summary>Signers the user trusts: their warnings are dropped.</summary>
    public HashSet<string> TrustedPublishers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Where the user's files live; tests point this at a temporary folder.</summary>
    public string UserProfile { get; init; } = KnownPaths.UserProfile;
    public string HostsFile { get; init; } = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

    public ICertificateSource Certificates { get; init; } = new SystemCertificates();

    private IReadOnlyList<StartupItem>? _startup;
    private IReadOnlyList<Apps.InstalledProgram>? _programs;
    private readonly Lock _lock = new();

    /// <summary>The installed desktop programs, read once and shared by the checks.</summary>
    public IReadOnlyList<Apps.InstalledProgram> Programs
    {
        get { lock (_lock) { return _programs ??= Apps.InstalledPrograms.All(includeStore: false); } }
        init => _programs = value;
    }

    /// <summary>The startup items, read once and shared by the checks.</summary>
    public IReadOnlyList<StartupItem> Startup
    {
        get { lock (_lock) { return _startup ??= StartupManager.List(includeServices: true); } }
        init => _startup = value;
    }

    /// <summary>Reads a text file of at most <paramref name="limit"/> bytes; null when missing, unreadable or larger.</summary>
    public static string? Text(string path, int limit = 1_000_000)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > limit || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) return null;
            return File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}

/// <summary>Where programs live and what their command lines say. Shared by several checks.</summary>
public static class Suspicion
{
    public static readonly string[] ScriptHosts = ["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe", "cmd.exe"];

    /// <summary>Folders a legitimate program never starts from.</summary>
    public static IEnumerable<string> DangerousFolders(string userProfile) =>
    [
        KnownPaths.Temp, Path.Combine(KnownPaths.Windows, "Temp"), Path.Combine(KnownPaths.SystemDrive, "$Recycle.Bin"), KnownPaths.Public,
        Path.Combine(userProfile, "Downloads"), Path.Combine(KnownPaths.ProgramData, "Temp"),
    ];

    public static bool IsInDangerousFolder(string path, string userProfile) =>
        DangerousFolders(userProfile).Any(d => PathGuard.IsStrictlyInside(path, d));

    /// <summary>Directly in AppData, ProgramData or the profile root, where programs do not live.</summary>
    public static bool IsBareDataFolder(string path, string userProfile)
    {
        string? dir = Path.GetDirectoryName(path);
        return dir is not null && new[] { KnownPaths.RoamingAppData, KnownPaths.LocalAppData, KnownPaths.ProgramData, userProfile }
            .Any(root => string.Equals(dir, root, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsHiddenFolder(string path) =>
        (Path.GetDirectoryName(path) ?? "").Split('\\').Any(c => c.StartsWith('.') && c.Length > 1);

    public static bool IsInWindows(string path) => PathGuard.IsStrictlyInside(path, KnownPaths.Windows);

    /// <summary>LOLBin patterns in a command line, with the reason.</summary>
    public static readonly (string Pattern, string Reason)[] CommandLinePatterns =
    [
        (@"(?i)-(enc|encodedcommand|e|ec)\s+[A-Za-z0-9+/=]{20,}", "PowerShell con comando codificato in base64"),
        (@"(?i)frombase64string", "Decodifica codice nascosto in base64"),
        (@"(?i)(iex|invoke-expression)\b", "Esegue codice costruito al volo (Invoke-Expression)"),
        (@"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\b|wget\b|curl\b).*https?://", "Scarica codice dalla rete"),
        (@"(?i)-w(indowstyle)?\s+hidden", "Finestra nascosta"),
        (@"(?i)mshta(\.exe)?\s+(https?:|javascript:|vbscript:)", "mshta esegue codice da una pagina o da uno script inline"),
        (@"(?i)rundll32(\.exe)?\s+.*(javascript:|https?://)", "rundll32 usato per eseguire codice da una pagina web"),
        (@"(?i)regsvr32(\.exe)?\s+.*(/i:|/s).*https?://", "regsvr32 carica codice dalla rete"),
        (@"(?i)certutil(\.exe)?\s+.*(-urlcache|-decode)", "certutil usato per scaricare o decodificare file"),
        (@"(?i)bitsadmin(\.exe)?\s+.*/transfer", "bitsadmin usato per scaricare file"),
        (@"(?i)msiexec(\.exe)?\s+.*/(i|package)\s+https?://", "msiexec installa un pacchetto da internet"),
        (@"(?i)schtasks(\.exe)?\s+.*/create", "Crea un'attività pianificata"),
        (@"(?i)reg(\.exe)?\s+add\s+.*\\run", "Aggiunge una voce di avvio automatico"),
        (@"(?i)vssadmin(\.exe)?\s+delete\s+shadows", "Cancella le copie shadow (ransomware)"),
        (@"(?i)wmic(\.exe)?\s+.*shadowcopy\s+delete", "Cancella le copie shadow (ransomware)"),
        (@"(?i)bcdedit(\.exe)?\s+.*recoveryenabled\s+no", "Disattiva il ripristino di Windows (ransomware)"),
        (@"(?i)set-mppreference|add-mppreference", "Modifica le impostazioni di Defender"),
        (@"(?i)-executionpolicy\s+bypass", "Aggira i criteri di esecuzione di PowerShell"),
    ];

    public static List<string> CommandLineReasons(string? command)
    {
        var reasons = new List<string>();
        if (string.IsNullOrEmpty(command)) return reasons;
        foreach (var (pattern, reason) in CommandLinePatterns)
            if (System.Text.RegularExpressions.Regex.IsMatch(command, pattern) && !reasons.Contains(reason)) reasons.Add(reason);
        return reasons;
    }
}

/// <summary>Verdicts already computed by a screen, with the real evaluator as fallback.</summary>
public sealed class CachedSignatures(Dictionary<string, SignatureInfo> cache) : ISignatureEvaluator
{
    public SignatureInfo Check(string path)
    {
        lock (cache)
        {
            if (cache.TryGetValue(path, out var hit)) return hit;
            var value = Signatures.Check(path);
            cache[path] = value;
            return value;
        }
    }
}
