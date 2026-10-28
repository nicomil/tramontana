using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>
/// COM hijacking: a CLSID registered under the user's hive wins over the
/// machine-wide one, so a DLL in the profile gets loaded by Explorer, Office
/// or the scheduled tasks that use that object. No prompt, no admin rights.
/// </summary>
public sealed class ComHijackCheck : IProtectionCheck
{
    public string Id => "com-hijack";
    public string Title => "Dirottamento COM";

    private const string UserClsid = @"HKEY_CURRENT_USER\Software\Classes\CLSID";
    private const string MachineClsid = @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();
        foreach (var clsid in r.SubKeys(UserClsid))
        {
            string userKey = $@"{UserClsid}\{clsid}";
            if (r.GetString($@"{userKey}\TreatAs", "") is { Length: > 0 } treatAs)
            {
                // Office and Windows register a few TreatAs entries per user: only a target outside the program folders counts.
                var target = r.GetString($@"{UserClsid}\{treatAs}\InprocServer32", "") ?? r.GetString($@"{MachineClsid}\{treatAs}\InprocServer32", "");
                string? targetPath = target is null ? null : Resolve(target);
                bool suspicious = targetPath is not null && !Suspicion.IsInWindows(targetPath) && !PathGuard.IsStrictlyInside(targetPath, KnownPaths.ProgramFiles)
                    && !PathGuard.IsStrictlyInside(targetPath, KnownPaths.ProgramFilesX86) && !(File.Exists(targetPath) && context.Signatures.Check(targetPath).Status == SignatureStatus.Signed);
                if (suspicious)
                    list.Add(new Finding($"com|treatas|{clsid}", Categories.Persistence, $"Oggetto COM reindirizzato: {clsid}",
                        $"TreatAs manda le richieste per questo oggetto a {treatAs}, cioè a «{targetPath}»: chi lo usa carica quel codice.", Severity.Danger)
                    { Path = targetPath, Evidence = [$@"{userKey}\TreatAs = {treatAs}", $"Destinazione: {targetPath}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo($@"{userKey}\TreatAs", "") });
            }
            if (r.GetString($@"{userKey}\ScriptletURL", "") is { Length: > 0 } scriptlet)
            {
                list.Add(new Finding($"com|scriptlet|{clsid}", Categories.Persistence, $"Oggetto COM da scriptlet remoto: {clsid}",
                    $"Il codice dell'oggetto viene scaricato da {scriptlet}.", Severity.Danger)
                { Path = userKey, Evidence = [$@"{userKey}\ScriptletURL = {scriptlet}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo($@"{userKey}\ScriptletURL", "") });
            }
            foreach (var server in new[] { "InprocServer32", "LocalServer32" })
            {
                var userPath = r.GetString($@"{userKey}\{server}", "");
                if (string.IsNullOrWhiteSpace(userPath)) continue;
                var machinePath = r.GetString($@"{MachineClsid}\{clsid}\{server}", "");
                string resolvedUser = Resolve(userPath);
                var evidence = new List<string> { $@"{userKey}\{server} = {userPath}" };
                if (machinePath is not null) evidence.Add($@"{MachineClsid}\{clsid}\{server} = {machinePath}");
                bool shadowsMachine = machinePath is not null && !string.Equals(Resolve(machinePath), resolvedUser, StringComparison.OrdinalIgnoreCase);
                var signature = File.Exists(resolvedUser) ? context.Signatures.Check(resolvedUser) : null;
                bool userFolder = !Suspicion.IsInWindows(resolvedUser) && !PathGuard.IsStrictlyInside(resolvedUser, KnownPaths.ProgramFiles) && !PathGuard.IsStrictlyInside(resolvedUser, KnownPaths.ProgramFilesX86);
                if (signature?.Publisher is not null) evidence.Add($"Firmato da: {signature.Publisher}");
                bool signed = signature?.Status == SignatureStatus.Signed;
                bool ownApp = Environment.ProcessPath is { } own && string.Equals(Path.GetDirectoryName(own), Path.GetDirectoryName(resolvedUser), StringComparison.OrdinalIgnoreCase);
                if (ownApp) continue;
                if (shadowsMachine)
                    list.Add(new Finding($"com|shadow|{clsid}|{server}", Categories.Persistence, signed ? $"Oggetto COM ridefinito nel profilo: {clsid}" : $"Oggetto COM di Windows dirottato: {clsid}",
                        $"Nel profilo utente lo stesso oggetto punta a «{resolvedUser}» invece che a quello di sistema: viene caricato da Explorer o dalle attività che lo usano, senza richieste."
                        + (signed ? $" La libreria è firmata da «{signature!.Publisher}»: di solito è un programma installato per il solo utente." : ""),
                        signed ? Severity.Warning : Severity.Danger)
                    { Path = resolvedUser, Evidence = [.. evidence], Action = signed ? FindingAction.None : FindingAction.Quarantine, Publisher = signature?.Publisher });
                else if (userFolder && server == "InprocServer32" && !signed && !resolvedUser.Contains(@"\AppData\Local\Microsoft\", StringComparison.OrdinalIgnoreCase))
                    list.Add(new Finding($"com|user|{clsid}|{server}", Categories.Persistence, $"Oggetto COM non firmato nel profilo: {Path.GetFileName(resolvedUser)}",
                        "Una libreria senza firma registrata nel profilo utente: i programmi che la usano la caricano senza controlli.", Severity.Warning)
                    { Path = resolvedUser, Evidence = [.. evidence], Action = FindingAction.DefenderScan, Publisher = signature?.Publisher });
            }
        }
        return list;
    }

    internal static string Resolve(string value)
    {
        string path = Environment.ExpandEnvironmentVariables(value.Trim());
        if (path.StartsWith('"')) { int end = path.IndexOf('"', 1); if (end > 0) path = path[1..end]; }
        else { int exe = path.IndexOf(".dll", StringComparison.OrdinalIgnoreCase); if (exe > 0) path = path[..(exe + 4)]; }
        if (!path.Contains('\\')) path = Path.Combine(Environment.SystemDirectory, path);
        return path;
    }
}
