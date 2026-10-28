using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>Windows's own defences: antivirus, Defender, firewall, UAC, SmartScreen, Secure Boot, Remote Desktop.</summary>
public sealed class DefencesCheck : IProtectionCheck
{
    public string Id => "defences";
    public string Title => "Difese di Windows";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        var registry = context.Registry;

        // Antivirus: Security Center lists the active product (Defender or another one).
        var products = context.Wmi.Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct")
            .Select(o => (Name: o.GetValueOrDefault("displayName") as string ?? "?", State: Convert.ToUInt32(o.GetValueOrDefault("productState") ?? 0u))).ToList();
        // productState: bits 12-15 = 1 means on, bits 4-7 = 0 means definitions up to date.
        var active = products.Where(p => ((p.State >> 12) & 0xF) == 1).ToList();
        if (products.Count > 0 && active.Count == 0)
            list.Add(new Finding("av-off", Categories.Defences, "Nessun antivirus attivo", "Windows non segnala nessun antivirus in funzione.", Severity.Danger)
            { SettingsLink = "windowsdefender://threat", Action = FindingAction.OpenSettings, Evidence = [.. products.Select(p => $"{p.Name}: stato 0x{p.State:X}")] });
        foreach (var p in active)
        {
            bool outdated = ((p.State >> 4) & 0xF) != 0;
            list.Add(new Finding($"av-{p.Name}", Categories.Defences, $"Antivirus: {p.Name}",
                outdated ? "Le definizioni dei virus non sono aggiornate." : "Attivo e aggiornato.", outdated ? Severity.Warning : Severity.Ok)
            { SettingsLink = "windowsdefender://threat", Action = FindingAction.OpenSettings, Evidence = [$"productState 0x{p.State:X}"] });
        }

        // Defender details (real-time protection, last scan).
        foreach (var o in context.Wmi.Query(@"root\Microsoft\Windows\Defender",
            "SELECT AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, QuickScanAge, IsTamperProtected FROM MSFT_MpComputerStatus"))
        {
            bool enabled = o.GetValueOrDefault("AntivirusEnabled") is true;
            if (enabled && o.GetValueOrDefault("RealTimeProtectionEnabled") is false)
                list.Add(new Finding("defender-realtime", Categories.Defences, "Protezione in tempo reale disattivata",
                    "Microsoft Defender non controlla i file mentre vengono aperti.", Severity.Danger) { SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings });
            if (enabled && o.GetValueOrDefault("QuickScanAge") is uint age && age > 30 && age != uint.MaxValue)
                list.Add(new Finding("defender-scan-age", Categories.Defences, "Nessuna analisi recente",
                    $"L'ultima analisi rapida di Defender risale a {age} giorni fa.", Severity.Info) { SettingsLink = "windowsdefender://threat", Action = FindingAction.OpenSettings });
            if (enabled && o.GetValueOrDefault("AntivirusSignatureAge") is uint signatureAge && signatureAge > 7)
                list.Add(new Finding("defender-signature-age", Categories.Defences, $"Definizioni di Defender vecchie di {signatureAge} giorni",
                    "Microsoft le aggiorna più volte al giorno: il PC non le sta ricevendo.", Severity.Warning) { SettingsLink = "windowsdefender://threat", Action = FindingAction.OpenSettings });
            if (o.GetValueOrDefault("IsTamperProtected") is false)
                list.Add(new Finding("defender-tamper", Categories.Defences, "Protezione anti-manomissione disattivata",
                    "Un programma potrebbe disattivare Defender senza che tu lo sappia.", Severity.Warning) { SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings });
        }

        // Firewall, per profile.
        foreach (var (profile, title) in new[] { ("StandardProfile", "privata"), ("PublicProfile", "pubblica"), ("DomainProfile", "di dominio") })
        {
            object? enabled = registry.GetValue($@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}", "EnableFirewall")
                ?? registry.GetValue($@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}", "EnableFirewall");
            if (enabled is int value && value == 0 && profile != "DomainProfile")
                list.Add(new Finding($"firewall-{profile}", Categories.Defences, $"Firewall disattivato per la rete {title}",
                    "Il PC accetta connessioni in entrata non richieste.", Severity.Danger) { SettingsLink = "windowsdefender://network", Action = FindingAction.OpenSettings, Evidence = [$"{profile}\\EnableFirewall = 0"] });
        }

        // UAC.
        const string system = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        if (registry.GetInt(system, "EnableLUA") == 0)
            list.Add(new Finding("uac-off", Categories.Defences, "Controllo account utente disattivato",
                "Ogni programma può modificare Windows senza chiedere conferma.", Severity.Danger) { Evidence = ["EnableLUA = 0"] });
        else if (registry.GetInt(system, "ConsentPromptBehaviorAdmin") == 0)
            list.Add(new Finding("uac-silent", Categories.Defences, "Controllo account utente silenzioso",
                "I programmi ottengono i permessi di amministratore senza che compaia la richiesta.", Severity.Warning) { Evidence = ["ConsentPromptBehaviorAdmin = 0"] });

        // SmartScreen.
        bool smartScreenOff = registry.GetInt(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") == 0
            || string.Equals(registry.GetString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"), "Off", StringComparison.OrdinalIgnoreCase);
        if (smartScreenOff)
            list.Add(new Finding("smartscreen-off", Categories.Defences, "SmartScreen disattivato",
                "Windows non avvisa più prima di aprire programmi scaricati poco diffusi.", Severity.Warning) { SettingsLink = "windowsdefender://appbrowser", Action = FindingAction.OpenSettings });

        // Secure Boot.
        if (registry.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 0)
            list.Add(new Finding("secureboot-off", Categories.Defences, "Avvio protetto disattivato",
                "Si attiva dalle impostazioni UEFI del PC: protegge dai programmi che si caricano prima di Windows.", Severity.Info));

        // Remote Desktop.
        if (registry.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0)
        {
            bool nla = registry.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication") != 0;
            list.Add(new Finding("rdp-on", Categories.Defences, nla ? "Desktop remoto attivo" : "Desktop remoto attivo senza autenticazione a livello di rete",
                nla ? "Altri computer possono collegarsi a questo PC. Disattivalo se non lo usi." : "Chiunque in rete arriva alla schermata di accesso: attiva l'autenticazione a livello di rete o spegni il Desktop remoto.",
                nla ? Severity.Info : Severity.Warning) { SettingsLink = "ms-settings:remotedesktop", Action = FindingAction.OpenSettings });
        }
        return list;
    }
}
