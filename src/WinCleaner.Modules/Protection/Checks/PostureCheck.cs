using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Settings that leave the PC open: credential theft, updates, Explorer's
/// hidden extensions, AutoPlay, SMBv1, remote access, accounts, automatic
/// sign-in, PowerShell and Office macros. Each one links to the place that
/// fixes it; the reversible ones in HKCU have a one-click fix.
/// </summary>
public sealed class PostureCheck : IProtectionCheck
{
    public string Id => "posture";
    public string Title => "Impostazioni di sicurezza";

    private const string Lsa = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa";
    private const string Winlogon = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Advanced = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    public const string Smb1Query = "SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol'";
    public const string HotfixQuery = "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering";
    public const string UsersQuery = "SELECT Name, Disabled, SID, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount = True";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        var r = context.Registry;
        void Add(string key, string title, string reason, Severity severity, string? link = null, string[]? evidence = null,
                 FindingAction action = FindingAction.None, string? path = null) =>
            list.Add(new Finding(key, Categories.Configuration, title, reason, severity)
            { SettingsLink = link, Evidence = evidence ?? [], Action = action != FindingAction.None ? action : link is null ? FindingAction.None : FindingAction.OpenSettings, Path = path });

        // Credentials in memory.
        if (r.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential") == 1)
            Add("wdigest", "Password conservate in chiaro in memoria (WDigest)",
                "Con questa impostazione chi ruba la memoria di LSASS legge la password: è una modifica tipica degli attaccanti.", Severity.Danger,
                evidence: ["WDigest [UseLogonCredential] = 1"], action: FindingAction.RemoveRegistryValue, path: @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest");
        if ((r.GetInt(Lsa, "RunAsPPL") ?? 0) == 0)
            Add("lsa-ppl", "LSASS non protetto", "Il processo che custodisce le credenziali può essere letto da un programma con i diritti di amministratore. Attiva «Protezione dell'autorità di sicurezza locale» in Sicurezza di Windows.",
                Severity.Info, "windowsdefender://devicesecurity", ["Lsa [RunAsPPL] assente o 0"]);

        // Updates.
        const string au = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
        if (r.GetInt(au, "NoAutoUpdate") == 1)
            Add("updates-off", "Aggiornamenti automatici disattivati da un criterio", "Windows non scarica più le correzioni di sicurezza.", Severity.Danger,
                "ms-settings:windowsupdate", ["WindowsUpdate\\AU [NoAutoUpdate] = 1"]);
        else if (r.GetInt(au, "AUOptions") == 1)
            Add("updates-notify-only", "Aggiornamenti solo su richiesta", "Windows avvisa ma non installa: le correzioni restano in attesa.", Severity.Warning, "ms-settings:windowsupdate", ["WindowsUpdate\\AU [AUOptions] = 1"]);
        if (r.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv", "Start") == 4)
            Add("updates-service", "Servizio Windows Update disattivato", "Senza questo servizio non arriva nessun aggiornamento, nemmeno di Defender.", Severity.Danger,
                "ms-settings:windowsupdate", ["Services\\wuauserv [Start] = 4"]);
        var hotfixes = context.Wmi.Query(@"root\cimv2", HotfixQuery).Select(h => DefenderCheck.ToDate(h.GetValueOrDefault("InstalledOn"))).Where(d => d is not null).Select(d => d!.Value).ToList();
        if (hotfixes.Count > 0 && (context.Now - hotfixes.Max()).TotalDays > 60)
            Add("updates-stale", $"Nessun aggiornamento installato da {(int)(context.Now - hotfixes.Max()).TotalDays} giorni",
                "Microsoft pubblica correzioni ogni mese: controlla che Windows Update funzioni.", Severity.Warning, "ms-settings:windowsupdate", [$"Ultimo aggiornamento: {hotfixes.Max():d}"]);

        // Explorer.
        if ((r.GetInt(Advanced, "HideFileExt") ?? 1) == 1)
            Add("explorer-hidefileext", "Estensioni dei file nascoste",
                "«fattura.pdf.exe» appare come «fattura.pdf»: il trucco più usato per far aprire un programma. Mostrale.", Severity.Warning,
                evidence: ["Explorer\\Advanced [HideFileExt] = 1"], action: FindingAction.FixSetting);

        // AutoPlay.
        bool autoplayOff = r.GetInt(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay") == 1
            || (r.GetInt(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun") ?? 0) == 0xFF
            || (r.GetInt(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun") ?? 0) == 0xFF;
        if (!autoplayOff)
            Add("autoplay", "AutoPlay attivo", "Chiavette e dischi esterni possono avviare qualcosa appena collegati. Disattivalo.", Severity.Info,
                "ms-settings:autoplay", action: FindingAction.FixSetting);

        // SMBv1.
        foreach (var feature in context.Wmi.Query(@"root\cimv2", Smb1Query))
            if (Convert.ToInt32(feature.GetValueOrDefault("InstallState") ?? 0) == 1)
                Add("smb1", "SMBv1 attivo", "Il protocollo di condivisione file del 2001, usato da WannaCry e NotPetya. Microsoft lo rimuove di default: disattivalo da «Attiva o disattiva funzionalità di Windows».",
                    Severity.Danger, "ms-settings:optionalfeatures", ["Win32_OptionalFeature SMB1Protocol: InstallState 1"]);

        // Remote access.
        if (r.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM", "Start") == 2)
            Add("winrm", "Gestione remota di Windows (WinRM) attiva", "Altri computer possono eseguire comandi su questo PC. Su un PC di casa non serve.", Severity.Warning, evidence: ["Services\\WinRM [Start] = 2"]);
        if (r.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start") == 2)
            Add("remote-registry", "Registro remoto attivo", "Altri computer possono leggere e modificare il registro di questo PC.", Severity.Warning, evidence: ["Services\\RemoteRegistry [Start] = 2"]);
        if (r.GetInt(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp") == 1)
            Add("remote-assistance", "Assistenza remota attiva", "Chi ha un invito può controllare il PC. Spegnila se non la usi con qualcuno di fidato.", Severity.Info, "ms-settings:remotedesktop",
                ["Remote Assistance [fAllowToGetHelp] = 1"]);

        // Accounts.
        var users = context.Wmi.Query(@"root\cimv2", UsersQuery);
        foreach (var u in users)
        {
            string name = u.GetValueOrDefault("Name") as string ?? "?";
            bool disabled = u.GetValueOrDefault("Disabled") is true;
            string sid = u.GetValueOrDefault("SID") as string ?? "";
            if (sid.EndsWith("-501") && !disabled)
                Add("guest", "Account Guest attivo", "Chiunque può entrare nel PC senza password.", Severity.Warning, "ms-settings:otherusers", [$"{name}: Disabled = False"]);
            if (sid.EndsWith("-500") && !disabled)
                Add("builtin-admin", "Account Administrator predefinito attivo", "È il bersaglio preferito degli attacchi da rete perché il nome è noto. Di norma è disattivato.", Severity.Warning, "ms-settings:otherusers", [$"{name}: Disabled = False"]);
            if (!disabled && u.GetValueOrDefault("PasswordRequired") is false && !sid.EndsWith("-503"))
                Add($"no-password|{name}", $"Account {name} senza password", "Chiunque davanti al PC o in rete può entrare.", Severity.Warning, "ms-settings:signinoptions", [$"{name}: PasswordRequired = False"]);
        }
        const string hiddenList = Winlogon + @"\SpecialAccounts\UserList";
        foreach (var name in r.ValueNames(hiddenList))
            if (r.GetInt(hiddenList, name) == 0)
                Add($"hidden-account|{name}", $"Account nascosto: {name}", "Non compare nella schermata di accesso: tecnica per tenere una porta aperta sul PC.", Severity.Danger,
                    "ms-settings:otherusers", [$"{hiddenList} [{name}] = 0"], FindingAction.RemoveRegistryValue, hiddenList);
        var admins = Admins(context.Commands.Run("net.exe", "localgroup", "Administrators"))
            .Where(a => !a.Equals("Administrator", StringComparison.OrdinalIgnoreCase) && !a.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase)).ToList();
        if (admins.Count > 0)
            Add("admins", $"Altri amministratori: {string.Join(", ", admins)}", "Ogni amministratore può installare qualsiasi cosa: controlla che siano tutti tuoi.", Severity.Info, "ms-settings:otherusers",
                [.. admins.Select(a => "Membro di Administrators: " + a)]);

        // Automatic sign-in.
        if (r.GetString(Winlogon, "AutoAdminLogon") == "1")
        {
            bool password = r.GetValue(Winlogon, "DefaultPassword") is not null;
            Add("autologon", password ? "Accesso automatico con la password scritta nel registro" : "Accesso automatico attivo",
                password ? "All'accensione entra da solo e la password è leggibile in chiaro da qualsiasi programma." : "All'accensione entra da solo senza chiedere la password.",
                password ? Severity.Danger : Severity.Warning, "ms-settings:signinoptions",
                [$"Winlogon [AutoAdminLogon] = 1", $"Winlogon [DefaultUserName] = {r.GetString(Winlogon, "DefaultUserName")}", password ? "Winlogon [DefaultPassword] presente" : ""]);
        }

        // PowerShell and scripts.
        var policy = r.GetString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy")
            ?? r.GetString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
        if (policy is not null && (policy.Equals("Unrestricted", StringComparison.OrdinalIgnoreCase) || policy.Equals("Bypass", StringComparison.OrdinalIgnoreCase)))
            Add("powershell-policy", $"Criterio di esecuzione PowerShell: {policy}", "Qualsiasi script scaricato parte senza avvisi. Il valore normale è RemoteSigned o Restricted.", Severity.Warning,
                evidence: [$"ExecutionPolicy = {policy}"]);

        // Office macros.
        foreach (var app in new[] { "Word", "Excel", "PowerPoint" })
        {
            foreach (var root in new[] { @"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0", @"HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0" })
            {
                string key = $@"{root}\{app}\Security";
                if (r.GetInt(key, "VBAWarnings") == 1)
                    Add($"office-macros|{app}", $"Macro di {app} attive senza avviso", "I documenti scaricati possono eseguire codice appena aperti: è così che arrivano Emotet e simili.", Severity.Danger,
                        evidence: [$"{key} [VBAWarnings] = 1"], action: FindingAction.FixSetting);
                if (r.GetInt(key, "BlockContentExecutionFromInternet") == 0)
                    Add($"office-motw|{app}", $"{app} esegue le macro dei file scaricati", "Office di norma blocca le macro nei file con il contrassegno di internet: qui è stato disattivato.", Severity.Warning,
                        evidence: [$"{key} [BlockContentExecutionFromInternet] = 0"]);
            }
        }

        // BitLocker, from the helper's evidence (manage-bde needs administrator rights).
        if (context.Evidence?["bitlocker"] is { } bitlocker)
        {
            string text = bitlocker.ToLowerInvariant();
            bool off = text.Contains("protezione disattivata") || text.Contains("protection off") || text.Contains("crittografia: nessuno") || text.Contains("encryption method: none");
            if (off)
                Add("bitlocker", "Disco di sistema non cifrato", "Chi prende il PC (o ne estrae il disco) legge tutti i file senza password. BitLocker o Crittografia dispositivo lo impediscono.", Severity.Warning,
                    "ms-settings:deviceencryption", [.. bitlocker.Split('\n').Select(l => l.Trim()).Where(l => l.Contains("rotezione") || l.Contains("rittografia") || l.Contains("rotection") || l.Contains("ncryption")).Take(6)]);
        }
        return list;
    }

    /// <summary>Members from `net localgroup Administrators`: the lines between the dashes and the closing sentence.</summary>
    internal static List<string> Admins(string output)
    {
        var members = new List<string>();
        bool inList = false;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("---")) { inList = true; continue; }
            if (!inList) continue;
            if (line.Length == 0 || line.Contains("riuscit", StringComparison.OrdinalIgnoreCase) || line.Contains("completed successfully", StringComparison.OrdinalIgnoreCase)) break;
            members.Add(line);
        }
        return members;
    }
}

/// <summary>The reversible one-click fixes of the posture findings (HKCU only).</summary>
public static class PostureFixes
{
    public static bool CanFix(string findingId) => findingId is "explorer-hidefileext" or "autoplay" || findingId.StartsWith("office-macros|");

    /// <summary>Applies the fix and returns what was done, or null when the id has no fix.</summary>
    public static string? Apply(string findingId)
    {
        using var hkcu = Microsoft.Win32.Registry.CurrentUser;
        string? done = null;
        if (findingId == "explorer-hidefileext")
        {
            using var key = hkcu.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", writable: true);
            key.SetValue("HideFileExt", 0, Microsoft.Win32.RegistryValueKind.DWord);
            done = "Le estensioni dei file ora sono visibili (riapri le finestre di Esplora risorse).";
        }
        else if (findingId == "autoplay")
        {
            using var key = hkcu.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", writable: true);
            key.SetValue("DisableAutoplay", 1, Microsoft.Win32.RegistryValueKind.DWord);
            done = "AutoPlay disattivato per questo utente.";
        }
        else if (findingId.StartsWith("office-macros|"))
        {
            string app = findingId["office-macros|".Length..];
            if (app is not ("Word" or "Excel" or "PowerPoint")) return null;
            using var key = hkcu.CreateSubKey($@"Software\Microsoft\Office\16.0\{app}\Security", writable: true);
            key.SetValue("VBAWarnings", 2, Microsoft.Win32.RegistryValueKind.DWord);
            done = $"Le macro di {app} ora chiedono conferma prima di partire.";
        }
        if (done is not null) OperationLog.Standard.Write($"posture\tfix\t{findingId}");
        return done;
    }
}
