using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Services that hide behind svchost with their own DLL, services with an
/// unquoted path, services running from user folders, and kernel drivers
/// outside the Windows folders or without a signature.
/// </summary>
public sealed class ServicesAndDriversCheck : IProtectionCheck
{
    public string Id => "services-drivers";
    public string Title => "Servizi e driver";

    private const string Services = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();
        foreach (var name in r.SubKeys(Services))
        {
            string key = $@"{Services}\{name}";
            int type = r.GetInt(key, "Type") ?? 0;
            int start = r.GetInt(key, "Start") ?? 3;
            if (start == 4) continue;
            var image = r.GetString(key, "ImagePath");
            if (string.IsNullOrWhiteSpace(image)) continue;
            string display = r.GetString(key, "DisplayName") is { } d && !d.StartsWith('@') ? d : name;

            if ((type & 0x30) != 0)
            {
                string expanded = Environment.ExpandEnvironmentVariables(image);
                // svchost-hosted: the real code is ServiceDll.
                if (expanded.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var dll = r.GetString($@"{key}\Parameters", "ServiceDll") ?? r.GetString(key, "ServiceDll");
                    if (dll is null) continue;
                    string path = Environment.ExpandEnvironmentVariables(dll);
                    bool inWindows = Suspicion.IsInWindows(path);
                    var signature = File.Exists(path) ? context.Signatures.Check(path) : null;
                    if (signature?.IsMicrosoft == true && inWindows) continue;
                    bool unsigned = signature is null || signature.Status != SignatureStatus.Signed;
                    list.Add(new Finding($"svchost|{name}", Categories.Persistence, $"Servizio dentro svchost: {display}",
                        (inWindows ? "La sua DLL è nella cartella di Windows ma non è firmata da Microsoft" : $"La sua DLL sta fuori da Windows ({Path.GetDirectoryName(path)})")
                        + (unsigned ? " e non è firmata." : $", firmata da «{signature!.Publisher}».") + " I servizi di sistema veri non fanno così.",
                        unsigned || !inWindows ? Severity.Danger : Severity.Warning)
                    { Path = path, Evidence = [$"{key} [ImagePath] = {image}", $"ServiceDll = {dll}", signature is null ? "File non trovato" : $"Firma: {signature.Status}"], Publisher = signature?.Publisher, Action = FindingAction.DefenderScan });
                    continue;
                }
                // Unquoted path with spaces: C:\Program Files\Vendor\svc.exe runs C:\Program.exe if it exists.
                if (!expanded.StartsWith('"'))
                {
                    int exe = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                    string head = exe > 0 ? expanded[..(exe + 4)] : expanded.Split(' ')[0];
                    if (head.Contains(' ') && !Suspicion.IsInWindows(head))
                        list.Add(new Finding($"unquoted|{name}", Categories.Persistence, $"Servizio con percorso senza virgolette: {display}",
                            "Windows prova prima «C:\\Program.exe», «C:\\Program Files\\Vendor.exe»…: un file messo lì parte come SYSTEM al posto del servizio.", Severity.Warning)
                        { Path = head, Evidence = [$"{key} [ImagePath] = {image}"] });
                }
                var exePath = Performance.StartupManager.ExecutableOf(expanded);
                if (exePath is not null && (Suspicion.IsInDangerousFolder(exePath, context.UserProfile) || PathGuard.IsStrictlyInside(exePath, context.UserProfile) || Suspicion.IsBareDataFolder(exePath, context.UserProfile)))
                    list.Add(new Finding($"usersvc|{name}", Categories.Persistence, $"Servizio avviato dal profilo utente: {display}",
                        $"Gira come servizio (spesso SYSTEM) ma il programma sta in {Path.GetDirectoryName(exePath)}: i servizi veri stanno in Program Files.", Severity.Warning)
                    { Path = exePath, Evidence = [$"{key} [ImagePath] = {image}"] });
            }
            else if (type is 1 or 2 && start <= 2)
            {
                string path = DriverPath(image);
                bool inSystem = Suspicion.IsInWindows(path);
                if (inSystem) continue; // Windows and DriverStore drivers are checked by Code Integrity already.
                var signature = File.Exists(path) ? context.Signatures.Check(path) : null;
                bool unsigned = signature is null || signature.Status != SignatureStatus.Signed;
                list.Add(new Finding($"driver|{name}", Categories.Persistence, $"Driver fuori da Windows: {display}",
                    (unsigned ? "Driver del kernel senza firma valida" : $"Driver del kernel firmato da «{signature!.Publisher}»") + $" in {Path.GetDirectoryName(path)}: un driver può fare qualsiasi cosa, Defender compreso.",
                    unsigned ? Severity.Danger : Severity.Info)
                { Path = path, Evidence = [$"{key} [ImagePath] = {image}", $"Tipo {type}, avvio {start}", signature is null ? "File non trovato" : $"Firma: {signature.Status}"], Publisher = signature?.Publisher });
            }
        }
        return list;
    }

    /// <summary>\SystemRoot\…, System32\drivers\…, \??\C:\… → full path.</summary>
    internal static string DriverPath(string image)
    {
        string p = image.Trim().Trim('"');
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = Path.Combine(KnownPaths.Windows, p[12..]);
        else if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"System32\", StringComparison.Ordinal)) p = Path.Combine(KnownPaths.Windows, p);
        else if (!p.Contains(':')) p = Path.Combine(KnownPaths.Windows, p.TrimStart('\\'));
        return Environment.ExpandEnvironmentVariables(p);
    }
}
