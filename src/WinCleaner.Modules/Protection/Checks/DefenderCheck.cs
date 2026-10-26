using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Microsoft Defender as malware leaves it: switched off by policy,
/// exclusions that hide folders from it, threats it caught recently, and the
/// protections that are off by default (ASR, network protection, controlled
/// folders).
/// </summary>
public sealed class DefenderCheck : IProtectionCheck
{
    public string Id => "defender";
    public string Title => "Microsoft Defender";

    private const string Policies = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string Scope = @"root\Microsoft\Windows\Defender";
    public const string PreferencesQuery = "SELECT ExclusionPath, ExclusionProcess, ExclusionExtension, DisableRealtimeMonitoring, EnableNetworkProtection, EnableControlledFolderAccess, AttackSurfaceReductionRules_Ids, PUAProtection FROM MSFT_MpPreference";
    public const string ThreatsQuery = "SELECT ThreatID, InitialDetectionTime, Resources, ActionSuccess, ThreatStatusID FROM MSFT_MpThreatDetection";
    public const string ThreatNamesQuery = "SELECT ThreatID, ThreatName, SeverityID FROM MSFT_MpThreat";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        var registry = context.Registry;

        // Policies: the first thing malware writes.
        foreach (var (key, value, title) in new[]
        {
            (Policies, "DisableAntiSpyware", "Defender disattivato da un criterio"),
            (Policies, "DisableAntiVirus", "Antivirus di Defender disattivato da un criterio"),
            (Policies + @"\Real-Time Protection", "DisableRealtimeMonitoring", "Protezione in tempo reale disattivata da un criterio"),
            (Policies + @"\Real-Time Protection", "DisableBehaviorMonitoring", "Monitoraggio del comportamento disattivato da un criterio"),
            (Policies + @"\Real-Time Protection", "DisableOnAccessProtection", "Protezione all'accesso disattivata da un criterio"),
        })
        {
            if (registry.GetInt(key, value) == 1)
                list.Add(new Finding($"defender-policy|{value}", Categories.Defences, title,
                    "Un criterio nel registro spegne Defender: sui PC di casa lo scrive il malware, non l'amministratore.", Severity.Danger)
                { Path = key, Evidence = [$"{key} [{value}] = 1"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo(key, value) });
        }

        // Preferences (exclusions are hidden from standard users on recent builds: the helper's evidence fills in).
        var preferences = context.Wmi.Query(Scope, PreferencesQuery).FirstOrDefault();
        var exclusions = new List<(string Kind, string Value)>();
        if (preferences is not null)
        {
            foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionPath"))) exclusions.Add(("Percorso", p));
            foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionProcess"))) exclusions.Add(("Processo", p));
            foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionExtension"))) exclusions.Add(("Estensione", p));
        }
        if (context.Evidence?["defender-exclusions"] is { } section)
        {
            foreach (var raw in section.Split('\n'))
            {
                var line = raw.Trim();
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                string kind = line[..colon].Trim().ToLowerInvariant() switch { "path" => "Percorso", "process" => "Processo", "extension" => "Estensione", _ => "" };
                if (kind.Length == 0) continue;
                var value = line[(colon + 1)..].Trim();
                if (value.Length > 0 && !exclusions.Contains((kind, value))) exclusions.Add((kind, value));
            }
        }
        foreach (var (kind, value) in exclusions)
        {
            var (severity, why) = Assess(kind, value, context.UserProfile);
            list.Add(new Finding($"defender-exclusion|{kind}|{value}", Categories.Defences, $"Esclusione di Defender: {value}", why, severity)
            { Path = kind == "Percorso" ? value : null, SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings, Evidence = [$"{kind}: {value}"] });
        }

        if (preferences is not null)
        {
            if (preferences.GetValueOrDefault("DisableRealtimeMonitoring") is true)
                list.Add(new Finding("defender-pref-realtime", Categories.Defences, "Protezione in tempo reale disattivata nelle preferenze",
                    "Defender non controlla i file mentre vengono aperti.", Severity.Danger) { SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings });
            if (Strings(preferences.GetValueOrDefault("AttackSurfaceReductionRules_Ids")).Length == 0)
                list.Add(new Finding("defender-asr", Categories.Defences, "Regole di riduzione della superficie di attacco non attive",
                    "Bloccano le macro di Office che avviano programmi, gli script scaricati e il furto di credenziali da LSASS. Si attivano da PowerShell con Add-MpPreference.", Severity.Info)
                { SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings });
            if (ToInt(preferences.GetValueOrDefault("EnableControlledFolderAccess")) == 0)
                list.Add(new Finding("defender-cfa", Categories.Defences, "Accesso controllato alle cartelle disattivato",
                    "Impedisce ai programmi sconosciuti di modificare Documenti e Immagini: la difesa più semplice contro i ransomware.", Severity.Info)
                { SettingsLink = "windowsdefender://ransomwareprotection", Action = FindingAction.OpenSettings });
            if (ToInt(preferences.GetValueOrDefault("EnableNetworkProtection")) == 0)
                list.Add(new Finding("defender-network", Categories.Defences, "Protezione di rete di Defender disattivata",
                    "Blocca le connessioni ai domini malevoli conosciuti da ogni programma, non solo dal browser.", Severity.Info)
                { SettingsLink = "windowsdefender://threatsettings", Action = FindingAction.OpenSettings });
            if (ToInt(preferences.GetValueOrDefault("PUAProtection")) == 0)
                list.Add(new Finding("defender-pua", Categories.Defences, "Blocco dei programmi indesiderati disattivato",
                    "Defender può bloccare adware e bundleware prima che si installino: è spento.", Severity.Warning)
                { SettingsLink = "windowsdefender://appbrowser", Action = FindingAction.OpenSettings });
        }

        // Threats of the last 30 days.
        var names = context.Wmi.Query(Scope, ThreatNamesQuery)
            .ToDictionary(r => Convert.ToInt64(r.GetValueOrDefault("ThreatID") ?? 0L), r => (Name: r.GetValueOrDefault("ThreatName") as string ?? "?", Severity: ToInt(r.GetValueOrDefault("SeverityID"))));
        foreach (var detection in context.Wmi.Query(Scope, ThreatsQuery))
        {
            var when = ToDate(detection.GetValueOrDefault("InitialDetectionTime"));
            if (when is null || (context.Now - when.Value).TotalDays > 30) continue;
            long threatId = Convert.ToInt64(detection.GetValueOrDefault("ThreatID") ?? 0L);
            var name = names.TryGetValue(threatId, out var n) ? n.Name : $"minaccia {threatId}";
            var resources = Strings(detection.GetValueOrDefault("Resources")).Select(r => r.StartsWith("file:_") ? r[6..] : r).ToArray();
            bool fixedUp = detection.GetValueOrDefault("ActionSuccess") is true;
            list.Add(new Finding($"defender-threat|{threatId}|{when:yyyyMMddHHmm}", Categories.Defences,
                $"Defender ha trovato {name}",
                (fixedUp ? "Rilevato e gestito da Defender il " : "Rilevato da Defender, azione NON riuscita, il ") + when.Value.ToString("d MMMM, HH:mm") + ". Controlla da dove è arrivato.",
                fixedUp ? Severity.Warning : Severity.Danger)
            { Path = resources.FirstOrDefault(r => r.Contains('\\')), SettingsLink = "windowsdefender://history", Action = FindingAction.OpenSettings,
              Evidence = [$"ThreatID {threatId}", .. resources.Take(10)] });
        }
        return list;
    }

    /// <summary>How much an exclusion hides. Whole drives, user folders and executable extensions hide everything.</summary>
    internal static (Severity Severity, string Reason) Assess(string kind, string value, string userProfile)
    {
        if (kind == "Estensione")
        {
            string ext = value.TrimStart('.').ToLowerInvariant();
            return ext is "exe" or "dll" or "ps1" or "js" or "vbs" or "bat" or "cmd" or "scr" or "com" or "msi" or "hta" or "jar" or "lnk" or "sys"
                ? (Severity.Danger, "Ogni file con questa estensione non viene più controllato: è il modo più semplice per far passare un malware.")
                : (Severity.Warning, "I file con questa estensione non vengono controllati.");
        }
        if (kind == "Processo")
            return (Severity.Warning, "Tutto ciò che questo programma apre o scrive non viene controllato.");
        string path = value.TrimEnd('\\');
        // Drive roots, any user's profile, AppData, Temp, Downloads, ProgramData, Windows, wildcards.
        bool broad = path.Length <= 3 || path.Contains('*')
            || path.Equals(userProfile, StringComparison.OrdinalIgnoreCase)
            || path.Equals(KnownPaths.ProgramData, StringComparison.OrdinalIgnoreCase)
            || path.Equals(KnownPaths.Windows, StringComparison.OrdinalIgnoreCase)
            || System.Text.RegularExpressions.Regex.IsMatch(path,
                @"(?i)^[a-z]:\\(users(\\[^\\]+(\\(appdata(\\(local|roaming|locallow)?(\\temp)?)?|downloads|desktop|documents))?)?|programdata|windows(\\temp)?|temp)$");
        return broad
            ? (Severity.Danger, "Esclude una cartella intera dove può finire qualsiasi cosa: Defender non vede più niente lì dentro.")
            : (Severity.Warning, "Questa cartella non viene controllata: va bene solo se sai perché c'è.");
    }

    internal static string[] Strings(object? value) => value switch
    {
        string[] array => array,
        string s when s.Length > 0 => [s],
        _ => [],
    };

    private static int ToInt(object? value) => value switch { null => 0, bool b => b ? 1 : 0, _ => Convert.ToInt32(value) };

    internal static DateTime? ToDate(object? value)
    {
        if (value is DateTime d) return d;
        if (value is string s)
        {
            // WMI DMTF form: 20261026164033.000000+060
            try { return System.Management.ManagementDateTimeConverter.ToDateTime(s); }
            catch (ArgumentOutOfRangeException) { }
            catch (FormatException) { }
            if (DateTime.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var invariant)) return invariant;
            if (DateTime.TryParse(s, out var parsed)) return parsed;
        }
        return null;
    }
}
