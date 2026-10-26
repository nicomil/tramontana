using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Performance;

namespace WinCleaner.Modules.Protection;

public enum Severity { Ok, Info, Warning, Danger }

/// <summary>One finding of the protection check, always with the reason.</summary>
public sealed record Finding(string Id, string Category, string Title, string Reason, Severity Severity)
{
    /// <summary>File or registry place the finding refers to, if any.</summary>
    public string? Path { get; init; }
    /// <summary>Settings page that fixes it (ms-settings: or windowsdefender: link).</summary>
    public string? SettingsLink { get; init; }
    public StartupItem? Startup { get; init; }
}

/// <summary>
/// Heuristic checks, without proprietary malware databases: Windows defences
/// (Defender, firewall, UAC, SmartScreen, Secure Boot), startup programs and
/// scheduled tasks that are unsigned, run scripts or live in unusual folders,
/// browser extensions not from the store, hosts file and proxy changes, and
/// devices whose driver reports a problem. Nothing is removed automatically:
/// each finding links to the place to act on.
/// </summary>
public static class ProtectionScanner
{
    public static List<Finding> Scan(IReadOnlyCollection<string>? ignored = null)
    {
        var findings = new List<Finding>();
        findings.AddRange(Defences());
        findings.AddRange(StartupChecks());
        findings.AddRange(BrowserExtensions());
        findings.AddRange(HostsAndProxy());
        findings.AddRange(DeviceProblems());
        if (ignored is { Count: > 0 }) findings.RemoveAll(f => ignored.Contains(f.Id));
        return findings.OrderByDescending(f => f.Severity).ToList();
    }

    // ---- Windows defences ----

    private static IEnumerable<Finding> Defences()
    {
        var list = new List<Finding>();
        // Antivirus: Security Center lists the active product (Defender or another one).
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            var products = searcher.Get().Cast<ManagementObject>()
                .Select(o => (Name: o["displayName"] as string ?? "?", State: Convert.ToUInt32(o["productState"]))).ToList();
            // productState: bits 12-15 = 1 means on, bits 4-7 = 0 means definitions up to date.
            var active = products.Where(p => ((p.State >> 12) & 0xF) == 1).ToList();
            if (active.Count == 0)
                list.Add(new Finding("av-off", "Difese di Windows", "Nessun antivirus attivo", "Windows non segnala nessun antivirus in funzione.", Severity.Danger)
                { SettingsLink = "windowsdefender://threat" });
            else
            {
                foreach (var p in active)
                {
                    bool outdated = ((p.State >> 4) & 0xF) != 0;
                    list.Add(new Finding($"av-{p.Name}", "Difese di Windows", $"Antivirus: {p.Name}",
                        outdated ? "Le definizioni dei virus non sono aggiornate." : "Attivo e aggiornato.", outdated ? Severity.Warning : Severity.Ok)
                    { SettingsLink = "windowsdefender://threat" });
                }
            }
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException) { }

        // Defender details (real-time protection, last scan).
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                "SELECT AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, QuickScanAge, IsTamperProtected FROM MSFT_MpComputerStatus");
            foreach (ManagementObject o in searcher.Get())
            {
                if (o["AntivirusEnabled"] is true && o["RealTimeProtectionEnabled"] is false)
                    list.Add(new Finding("defender-realtime", "Difese di Windows", "Protezione in tempo reale disattivata",
                        "Microsoft Defender non controlla i file mentre vengono aperti.", Severity.Danger) { SettingsLink = "windowsdefender://threatsettings" });
                if (o["AntivirusEnabled"] is true && o["QuickScanAge"] is uint age && age > 30 && age != uint.MaxValue)
                    list.Add(new Finding("defender-scan-age", "Difese di Windows", "Nessuna analisi recente",
                        $"L'ultima analisi rapida di Defender risale a {age} giorni fa.", Severity.Info) { SettingsLink = "windowsdefender://threat" });
                if (o["IsTamperProtected"] is false)
                    list.Add(new Finding("defender-tamper", "Difese di Windows", "Protezione anti-manomissione disattivata",
                        "Un programma potrebbe disattivare Defender senza che tu lo sappia.", Severity.Warning) { SettingsLink = "windowsdefender://threatsettings" });
            }
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException) { }

        // Firewall, per profile.
        foreach (var (profile, title) in new[] { ("StandardProfile", "privata"), ("PublicProfile", "pubblica"), ("DomainProfile", "di dominio") })
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}");
            using var policy = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}");
            object? enabled = policy?.GetValue("EnableFirewall") ?? key?.GetValue("EnableFirewall");
            if (enabled is int value && value == 0 && profile != "DomainProfile")
                list.Add(new Finding($"firewall-{profile}", "Difese di Windows", $"Firewall disattivato per la rete {title}",
                    "Il PC accetta connessioni in entrata non richieste.", Severity.Danger) { SettingsLink = "windowsdefender://network" });
        }

        // UAC.
        using (var system = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
        {
            if (system?.GetValue("EnableLUA") is int lua && lua == 0)
                list.Add(new Finding("uac-off", "Difese di Windows", "Controllo account utente disattivato",
                    "Ogni programma può modificare Windows senza chiedere conferma.", Severity.Danger));
            else if (system?.GetValue("ConsentPromptBehaviorAdmin") is int consent && consent == 0)
                list.Add(new Finding("uac-silent", "Difese di Windows", "Controllo account utente silenzioso",
                    "I programmi ottengono i permessi di amministratore senza che compaia la richiesta.", Severity.Warning));
        }

        // SmartScreen.
        using (var explorer = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"))
        using (var policy = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System"))
        {
            bool off = policy?.GetValue("EnableSmartScreen") is int p && p == 0
                       || string.Equals(explorer?.GetValue("SmartScreenEnabled") as string, "Off", StringComparison.OrdinalIgnoreCase);
            if (off)
                list.Add(new Finding("smartscreen-off", "Difese di Windows", "SmartScreen disattivato",
                    "Windows non avvisa più prima di aprire programmi scaricati poco diffusi.", Severity.Warning) { SettingsLink = "windowsdefender://appbrowser" });
        }

        // Secure Boot.
        using (var secure = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
        {
            if (secure?.GetValue("UEFISecureBootEnabled") is int sb && sb == 0)
                list.Add(new Finding("secureboot-off", "Difese di Windows", "Avvio protetto disattivato",
                    "Si attiva dalle impostazioni UEFI del PC: protegge dai programmi che si caricano prima di Windows.", Severity.Info));
        }

        // Remote Desktop.
        using (var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
        {
            if (ts?.GetValue("fDenyTSConnections") is int deny && deny == 0)
                list.Add(new Finding("rdp-on", "Difese di Windows", "Desktop remoto attivo",
                    "Altri computer possono collegarsi a questo PC. Disattivalo se non lo usi.", Severity.Info) { SettingsLink = "ms-settings:remotedesktop" });
        }
        return list;
    }

    // ---- Startup programs and tasks ----

    private static readonly string[] ScriptHosts = ["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe"];

    internal static (Severity Severity, string Reason)? Assess(StartupItem item)
    {
        if (item.IsBroken) return null;
        string? exe = item.Executable;
        if (exe is null) return null;
        string name = Path.GetFileName(exe);
        string command = item.Command ?? "";

        string[] dangerous = [KnownPaths.Temp, Path.Combine(KnownPaths.Windows, "Temp"), Path.Combine(KnownPaths.SystemDrive, "$Recycle.Bin"), KnownPaths.Public];
        if (dangerous.Any(d => PathGuard.IsStrictlyInside(exe, d)))
            return (Severity.Danger, $"Parte da una cartella temporanea o condivisa ({Path.GetDirectoryName(exe)}).");

        if (ScriptHosts.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            bool encoded = command.Contains("-enc", StringComparison.OrdinalIgnoreCase) || command.Contains("frombase64", StringComparison.OrdinalIgnoreCase)
                           || command.Contains("http", StringComparison.OrdinalIgnoreCase) || command.Contains("-w hidden", StringComparison.OrdinalIgnoreCase)
                           || command.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase);
            return encoded
                ? (Severity.Danger, "Esegue uno script nascosto o scaricato da internet.")
                : (Severity.Warning, $"Esegue uno script con {name} all'avvio.");
        }
        if (name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) && (command.Contains("javascript:", StringComparison.OrdinalIgnoreCase) || command.Contains("http", StringComparison.OrdinalIgnoreCase)))
            return (Severity.Danger, "rundll32 usato per eseguire codice da una pagina web.");

        // Directly in AppData or ProgramData, not in a program's own folder.
        foreach (var root in new[] { KnownPaths.RoamingAppData, KnownPaths.LocalAppData, KnownPaths.ProgramData })
            if (string.Equals(Path.GetDirectoryName(exe), root, StringComparison.OrdinalIgnoreCase))
                return (Severity.Warning, $"Il programma sta direttamente in {root}, dove di solito non ci sono eseguibili.");

        var signature = item.Signature;
        if (signature?.Status == SignatureStatus.Invalid)
            return (Severity.Danger, "La firma digitale del programma non è valida: il file potrebbe essere stato modificato.");
        if (signature?.Status == SignatureStatus.Unsigned)
        {
            bool hidden = Path.GetDirectoryName(exe)!.Split('\\').Any(c => c.StartsWith('.') && c.Length > 1);
            return hidden
                ? (Severity.Warning, "Programma senza firma digitale in una cartella nascosta.")
                : (Severity.Info, "Programma senza firma digitale: controlla di conoscerlo.");
        }
        if (signature?.Status == SignatureStatus.Signed && signature.IsMicrosoft == false
            && (item.Name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) || item.Name.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
            && !string.IsNullOrEmpty(signature.Publisher))
            return (Severity.Warning, $"Si chiama come un componente di Windows ma è firmato da «{signature.Publisher}».");
        return null;
    }

    private static IEnumerable<Finding> StartupChecks()
    {
        foreach (var item in StartupManager.List(includeServices: true))
        {
            if (Assess(item) is not { } assessment) continue;
            yield return new Finding($"startup|{item.Id}", "Avvio automatico", item.Name, assessment.Reason, assessment.Severity)
            {
                Path = item.Executable,
                Startup = item,
            };
        }
    }

    // ---- Browser extensions ----

    private static IEnumerable<Finding> BrowserExtensions()
    {
        foreach (var browser in BrowserCatalog.Chromium)
        {
            string? userData = KnownPaths.Expand(browser.UserData);
            if (userData is null || !Directory.Exists(userData)) continue;
            var profiles = browser.ProfileIsRoot ? [userData] : Directory.EnumerateDirectories(userData)
                .Where(d => File.Exists(Path.Combine(d, "Preferences"))).ToList();
            foreach (var profile in profiles)
                foreach (var finding in ChromiumExtensions(browser, profile)) yield return finding;
        }
    }

    /// <summary>
    /// Where an extension came from is read from what the browser recorded in
    /// the profile ("location", "from_webstore"), not from the extension's own
    /// manifest, which anyone can write.
    /// </summary>
    /// <summary>Extensions the browsers install on their own (Docs Offline, Web Store payments, Media Router).</summary>
    private static readonly HashSet<string> DefaultExtensions =
        ["ghbmnnjooekpmoecnnnilnnbdlolhkhi", "nmmhkkegccagdldgiimedpiccmgmieda", "pkedcjkdefgpdelpbcmbmeomcjbeemfm", "mhjfbmdgcfjbbpaeojofohoefgiehjai"];

    internal static IEnumerable<Finding> ChromiumExtensions(ChromiumBrowser browser, string profile)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>();
        foreach (var file in new[] { "Secure Preferences", "Preferences" })
        {
            string path = Path.Combine(profile, file);
            if (!File.Exists(path)) continue;
            JsonDocument doc;
            try { doc = JsonDocument.Parse(File.ReadAllText(path)); }
            catch (Exception e) when (e is IOException or JsonException) { continue; }
            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("extensions", out var ext) || !ext.TryGetProperty("settings", out var settings)) continue;
                foreach (var entry in settings.EnumerateObject())
                {
                    var s = entry.Value;
                    // Entries without a location are leftovers of removed or built-in extensions.
                    if (!s.TryGetProperty("location", out var l) || !l.TryGetInt32(out var location)) continue;
                    if (!seen.Add(entry.Name) || DefaultExtensions.Contains(entry.Name)) continue;
                    if (location is 5 or 10) continue; // component extensions of the browser
                    bool fromStore = s.TryGetProperty("from_webstore", out var w) && w.ValueKind == JsonValueKind.True;
                    bool defaultInstall = s.TryGetProperty("was_installed_by_default", out var d) && d.ValueKind == JsonValueKind.True;
                    string name = entry.Name;
                    if (s.TryGetProperty("manifest", out var manifest) && manifest.TryGetProperty("name", out var n) && n.GetString() is { } mn && !mn.StartsWith("__MSG_"))
                        name = mn;
                    bool broad = false;
                    foreach (var key in new[] { "active_permissions", "granted_permissions" })
                    {
                        if (!s.TryGetProperty(key, out var perms)) continue;
                        foreach (var listName in new[] { "explicit_host", "scriptable_host" })
                            if (perms.TryGetProperty(listName, out var hosts) && hosts.ValueKind == JsonValueKind.Array)
                                broad |= hosts.EnumerateArray().Any(h => h.GetString() is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*");
                    }

                    // Edge records store installs as internal without from_webstore.
                    bool storeLike = fromStore || defaultInstall || (browser.Id.StartsWith("edge") && location == 1);
                    (Severity, string)? verdict = location switch
                    {
                        2 or 3 or 6 => (Severity.Warning, "Installata da un altro programma, non da te dal negozio delle estensioni."),
                        4 or 8 => (Severity.Info, "Estensione caricata in modalità sviluppatore."),
                        7 or 9 => (Severity.Info, "Imposta da un criterio (azienda, scuola o un programma installato)."),
                        _ when !storeLike => (Severity.Warning, "Non viene dal negozio delle estensioni."),
                        _ when broad => (Severity.Info, "Può leggere e modificare i dati di tutti i siti che visiti."),
                        _ => null,
                    };
                    if (verdict is { } v)
                        findings.Add(new Finding($"ext|{browser.Id}|{Path.GetFileName(profile)}|{entry.Name}", "Estensioni dei browser",
                            $"{name} ({browser.Name})", v.Item2, v.Item1) { Path = Path.Combine(profile, "Extensions", entry.Name) });
                }
            }
        }
        return findings;
    }

    // ---- Hosts and proxy ----

    private static IEnumerable<Finding> HostsAndProxy()
    {
        var list = new List<Finding>();
        var hosts = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
        try
        {
            var entries = File.ReadLines(hosts).Select(l => l.Split('#')[0].Trim()).Where(l => l.Length > 0).ToList();
            var redirects = entries.Where(e =>
            {
                var parts = e.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 2 && parts[0] is not ("127.0.0.1" or "::1" or "0.0.0.0") && parts[1] != "localhost";
            }).ToList();
            if (redirects.Count > 0)
                list.Add(new Finding("hosts-redirect", "Rete", "Il file hosts reindirizza dei siti",
                    $"{redirects.Count} nomi portano a indirizzi diversi, per esempio «{redirects[0]}». Può servire per sviluppo o essere un dirottamento.", Severity.Warning)
                { Path = hosts });
            else if (entries.Count > 20)
                list.Add(new Finding("hosts-block", "Rete", "Il file hosts blocca dei siti", $"{entries.Count} voci (spesso un blocco della pubblicità).", Severity.Info) { Path = hosts });
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        using var internet = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
        if (internet?.GetValue("ProxyEnable") is int proxy && proxy == 1)
            list.Add(new Finding("proxy-on", "Rete", "Proxy attivo", $"Il traffico web passa da {internet.GetValue("ProxyServer")}. Va bene solo se l'hai impostato tu o la tua azienda.", Severity.Warning)
            { SettingsLink = "ms-settings:network-proxy" });
        if (internet?.GetValue("AutoConfigURL") is string pac && pac.Length > 0)
            list.Add(new Finding("proxy-pac", "Rete", "Configurazione automatica del proxy", $"Script di configurazione: {pac}.", Severity.Warning)
            { SettingsLink = "ms-settings:network-proxy" });
        return list;
    }

    // ---- Devices ----

    private static IEnumerable<Finding> DeviceProblems()
    {
        var list = new List<Finding>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, DeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
            foreach (ManagementObject o in searcher.Get())
            {
                uint code = Convert.ToUInt32(o["ConfigManagerErrorCode"]);
                if (code == 22) continue; // disabled by the user
                string name = o["Name"] as string ?? (o["DeviceID"] as string ?? "Dispositivo");
                string reason = code switch
                {
                    28 => "Il driver non è installato.",
                    10 => "Il dispositivo non si avvia.",
                    43 => "Windows ha fermato il dispositivo perché ha segnalato problemi.",
                    45 => "Il dispositivo non è collegato.",
                    _ => $"Gestione dispositivi segnala il codice {code}.",
                };
                if (code == 45) continue;
                list.Add(new Finding($"device|{o["DeviceID"]}", "Driver e dispositivi", name, reason, Severity.Info) { SettingsLink = "ms-settings:windowsupdate-optionalupdates" });
            }
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException) { }
        return list;
    }

    /// <summary>Starts a Microsoft Defender quick scan and waits for it.</summary>
    public static async Task<string> DefenderQuickScanAsync(CancellationToken cancellation)
    {
        var mpcmd = Path.Combine(KnownPaths.ProgramFiles, "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(mpcmd)) return "Microsoft Defender non è disponibile";
        var (exit, output) = await Maintenance.Exec(mpcmd, ["-Scan", "-ScanType", "1"], cancellation);
        return exit switch
        {
            0 => "Analisi rapida completata: nessuna minaccia",
            2 => "Defender ha trovato delle minacce: aprile in Sicurezza di Windows",
            _ => $"Analisi terminata con codice {exit}",
        };
    }
}
