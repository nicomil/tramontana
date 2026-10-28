using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>
/// Scripts that run by themselves: PowerShell profiles (every console), the
/// Office start-up folders and templates (every document), and the COM
/// add-ins of Office.
/// </summary>
public sealed class ScriptsAndOfficeCheck : IProtectionCheck
{
    public string Id => "scripts-office";
    public string Title => "Profili PowerShell e Office";
    private readonly int _recentDays;

    public ScriptsAndOfficeCheck(int recentDays = 30) => _recentDays = recentDays;

    public IEnumerable<string> ProfilePaths(CheckContext context)
    {
        string documents = Path.Combine(context.UserProfile, "Documents");
        yield return Path.Combine(documents, "WindowsPowerShell", "profile.ps1");
        yield return Path.Combine(documents, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1");
        yield return Path.Combine(documents, "WindowsPowerShell", "Microsoft.PowerShellISE_profile.ps1");
        yield return Path.Combine(documents, "PowerShell", "profile.ps1");
        yield return Path.Combine(documents, "PowerShell", "Microsoft.PowerShell_profile.ps1");
        yield return Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "profile.ps1");
        yield return Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Microsoft.PowerShell_profile.ps1");
        yield return Path.Combine(KnownPaths.ProgramFiles, "PowerShell", "7", "profile.ps1");
        yield return Path.Combine(KnownPaths.ProgramFiles, "PowerShell", "7", "Microsoft.PowerShell_profile.ps1");
    }

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        foreach (var profile in ProfilePaths(context))
        {
            var text = CheckContext.Text(profile, 2_000_000);
            if (text is null) continue;
            var reasons = new List<string>();
            var evidence = new List<string>();
            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                var found = Suspicion.CommandLineReasons(line);
                if (found.Count == 0) continue;
                foreach (var f in found) if (!reasons.Contains(f)) reasons.Add(f);
                if (evidence.Count < 20) evidence.Add(line.Length > 300 ? line[..300] : line);
            }
            var modified = File.GetLastWriteTime(profile);
            if (reasons.Count > 0)
                list.Add(new Finding($"psprofile|{profile}", Categories.Persistence, $"Profilo PowerShell: {Path.GetFileName(profile)}",
                    "Parte a ogni finestra PowerShell, anche quelle aperte dalle attività di sistema. " + string.Join(". ", reasons) + ".", Severity.Danger)
                { Path = profile, Evidence = [.. evidence], Action = FindingAction.Quarantine });
            else if ((context.Now - modified).TotalDays < _recentDays)
                list.Add(new Finding($"psprofile|{profile}", Categories.Persistence, $"Profilo PowerShell modificato di recente: {Path.GetFileName(profile)}",
                    $"Modificato il {modified:d}: parte a ogni finestra PowerShell. Controlla che sia opera tua.", Severity.Info) { Path = profile });
        }

        // Office start-up folders and the Normal template.
        string roaming = Path.Combine(context.UserProfile, "AppData", "Roaming", "Microsoft");
        foreach (var (folder, app) in new[] { (Path.Combine(roaming, "Excel", "XLSTART"), "Excel"), (Path.Combine(roaming, "Word", "STARTUP"), "Word"), (Path.Combine(roaming, "AddIns"), "Office") })
        {
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                var modified = File.GetLastWriteTime(file);
                list.Add(new Finding($"officestart|{file}", Categories.Persistence, $"Avvio automatico di {app}: {Path.GetFileName(file)}",
                    $"Si apre con {app} ogni volta, macro comprese. Modificato il {modified:d}.", (context.Now - modified).TotalDays < _recentDays ? Severity.Warning : Severity.Info)
                { Path = file, Action = FindingAction.Quarantine });
            }
        }
        string normal = Path.Combine(roaming, "Templates", "Normal.dotm");
        if (File.Exists(normal) && (context.Now - File.GetLastWriteTime(normal)).TotalDays < _recentDays)
        {
            var info = new FileInfo(normal);
            // The plain template is ~20 KB; macros make it grow.
            list.Add(new Finding("normal-dotm", Categories.Persistence, "Modello Normal.dotm di Word modificato di recente",
                $"Ogni documento nuovo parte da qui, macro comprese. Modificato il {info.LastWriteTime:d}, {Format.Bytes(info.Length)}.", info.Length > 100_000 ? Severity.Warning : Severity.Info)
            { Path = normal });
        }

        // COM add-ins.
        foreach (var hive in new[] { "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE" })
            foreach (var app in new[] { "Word", "Excel", "PowerPoint", "Outlook" })
            {
                string key = $@"{hive}\Software\Microsoft\Office\{app}\Addins";
                foreach (var addin in context.Registry.SubKeys(key))
                {
                    if (context.Registry.GetInt($@"{key}\{addin}", "LoadBehavior") is not 3) continue;
                    string? dll = AddinPath(context, addin);
                    var signature = dll is not null && File.Exists(dll) ? context.Signatures.Check(dll) : null;
                    if (signature?.IsMicrosoft == true) continue;
                    bool unsigned = dll is not null && (signature is null || signature.Status != SignatureStatus.Signed);
                    list.Add(new Finding($"addin|{hive}|{app}|{addin}", Categories.Persistence, $"Componente aggiuntivo di {app}: {context.Registry.GetString($@"{key}\{addin}", "FriendlyName") ?? addin}",
                        (unsigned ? "Non firmato: " : "") + $"si carica a ogni avvio di {app}.", unsigned ? Severity.Warning : Severity.Info)
                    { Path = dll, Evidence = [$@"{key}\{addin}", dll is null ? "Percorso non risolto" : $"DLL: {dll}", signature?.Publisher is null ? "" : "Firmato da: " + signature.Publisher], Publisher = signature?.Publisher });
                }
            }
        return list;
    }

    private static string? AddinPath(CheckContext context, string progId)
    {
        foreach (var root in new[] { @"HKEY_CURRENT_USER\Software\Classes", @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes" })
        {
            var clsid = context.Registry.GetString($@"{root}\{progId}\CLSID", "");
            if (clsid is null) continue;
            var dll = context.Registry.GetString($@"{root}\CLSID\{clsid}\InprocServer32", "");
            if (dll is not null) return ComHijackCheck.Resolve(dll);
            // .NET add-ins: the manifest path.
            var manifest = context.Registry.GetString($@"HKEY_CURRENT_USER\Software\Microsoft\Office\{progId}", "Manifest");
            if (manifest is not null) return manifest.Split('|')[0].Replace("file:///", "").Replace('/', '\\');
        }
        return null;
    }
}
