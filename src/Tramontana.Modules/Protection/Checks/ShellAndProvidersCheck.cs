using System.Text;
using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>
/// DLLs Windows loads into its own processes by configuration: Active Setup
/// stubs, LSA packages (credentials), shell hooks and browser helper objects
/// (Explorer), print monitors (spooler, as SYSTEM), netsh helpers and
/// Winsock providers (every program that opens a socket).
/// </summary>
public sealed class ShellAndProvidersCheck : IProtectionCheck
{
    public string Id => "shell-providers";
    public string Title => "Componenti caricati da Windows";

    private static readonly HashSet<string> KnownLsa = new(StringComparer.OrdinalIgnoreCase)
        { "msv1_0", "scecli", "rassfm", "kerberos", "negotiate", "pku2u", "cloudap", "wdigest", "tspkg", "schannel", "wsauth", "msapsspc", "msnsspc", "negoexts", "livessp", "", "\"\"" };

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();

        // Active Setup: StubPath runs once per user at sign-in.
        foreach (var root in new[] { @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components", @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" })
            foreach (var component in r.SubKeys(root))
            {
                var stub = r.GetString($@"{root}\{component}", "StubPath");
                if (string.IsNullOrWhiteSpace(stub)) continue;
                var exe = Performance.StartupManager.ExecutableOf(stub);
                if (exe is null || Suspicion.IsInWindows(exe)) continue;
                var signature = File.Exists(exe) ? context.Signatures.Check(exe) : null;
                if (signature?.IsMicrosoft == true) continue;
                var reasons = Suspicion.CommandLineReasons(stub);
                bool bad = reasons.Count > 0 || Suspicion.IsInDangerousFolder(exe, context.UserProfile) || signature?.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid or SignatureStatus.Untrusted;
                list.Add(new Finding($"activesetup|{component}", Categories.Persistence, $"Active Setup: {r.GetString($@"{root}\{component}", "") ?? component}",
                    (bad ? "Parte una volta per ogni utente al primo accesso, e questo comando non è di un programma firmato. " : "Parte una volta per ogni utente al primo accesso. ")
                    + (reasons.Count > 0 ? string.Join(". ", reasons) + "." : ""), bad ? Severity.Danger : Severity.Info)
                { Path = exe, Evidence = [$@"{root}\{component} [StubPath] = {stub}", signature?.Publisher is null ? "Non firmato" : "Firmato da: " + signature.Publisher], Publisher = signature?.Publisher,
                  Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo($@"{root}\{component}", "StubPath") });
            }

        // LSA: packages that see every password typed.
        const string lsa = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa";
        foreach (var value in new[] { "Authentication Packages", "Notification Packages", "Security Packages" })
            foreach (var package in r.GetStrings(lsa, value).Concat(r.GetStrings(lsa + @"\OSConfig", value)))
                if (!KnownLsa.Contains(package.Trim()))
                    list.Add(new Finding($"lsa|{value}|{package}", Categories.Persistence, $"Pacchetto LSA sconosciuto: {package}",
                        $"Una DLL in «{value}» viene caricata da LSASS e vede ogni accesso e ogni cambio di password.", Severity.Danger)
                    { Path = Path.Combine(Environment.SystemDirectory, package.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? package : package + ".dll"), Evidence = [$"{lsa} [{value}] contiene {package}"] });

        // Explorer hooks and browser helper objects.
        foreach (var (key, title) in new[]
        {
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "Hook di esecuzione della shell"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "Oggetto caricato da Explorer"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "Browser Helper Object"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "Browser Helper Object (32 bit)"),
            (@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "Oggetto caricato da Explorer (utente)"),
        })
        {
            var entries = r.SubKeys(key).Select(s => (Clsid: s, Key: $@"{key}\{s}")).ToList();
            foreach (var name in r.ValueNames(key)) if (r.GetString(key, name) is { } clsid && clsid.StartsWith('{')) entries.Add((clsid, key + " [" + name + "]"));
            foreach (var (clsid, source) in entries)
                AddClsidFinding(list, context, clsid, source, title, Severity.Warning);
        }

        // Print monitors and providers run inside the spooler as SYSTEM.
        foreach (var (root, value, title) in new[]
        {
            (@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors", "Driver", "Monitor di stampa"),
            (@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers", "Name", "Provider di stampa"),
        })
            foreach (var sub in r.SubKeys(root))
            {
                var dll = r.GetString($@"{root}\{sub}", value);
                if (string.IsNullOrWhiteSpace(dll)) continue;
                string path = dll.Contains('\\') ? dll : Path.Combine(Environment.SystemDirectory, dll);
                AddDllFinding(list, context, path, $"{title}: {sub}", $@"{root}\{sub} [{value}] = {dll}", "Viene caricata dallo spooler di stampa con i diritti di SYSTEM.");
            }

        // netsh helpers.
        const string netsh = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh";
        foreach (var name in r.ValueNames(netsh))
        {
            var dll = r.GetString(netsh, name);
            if (string.IsNullOrWhiteSpace(dll)) continue;
            string path = dll.Contains('\\') ? dll : Path.Combine(Environment.SystemDirectory, dll);
            AddDllFinding(list, context, path, $"Helper di netsh: {name}", $"{netsh} [{name}] = {dll}", "Viene caricata ogni volta che netsh parte (anche dalle attività di sistema).");
        }

        // Winsock providers: PackedCatalogItem starts with the DLL path.
        const string winsock = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters";
        foreach (var catalog in new[] { "Protocol_Catalog9\\Catalog_Entries", "Protocol_Catalog9\\Catalog_Entries64" })
            foreach (var entry in r.SubKeys($@"{winsock}\{catalog}"))
            {
                if (r.GetValue($@"{winsock}\{catalog}\{entry}", "PackedCatalogItem") is not byte[] packed) continue;
                string dll = Encoding.ASCII.GetString(packed.TakeWhile(b => b != 0).ToArray());
                if (dll.Length == 0) continue;
                string path = Environment.ExpandEnvironmentVariables(dll);
                if (Suspicion.IsInWindows(path) || dll.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)) continue;
                AddDllFinding(list, context, path, $"Provider Winsock: {Path.GetFileName(path)}", $@"{winsock}\{catalog}\{entry}: {dll}", "Vede tutto il traffico di rete di ogni programma (LSP).");
            }
        foreach (var catalog in new[] { "NameSpace_Catalog5\\Catalog_Entries", "NameSpace_Catalog5\\Catalog_Entries64" })
            foreach (var entry in r.SubKeys($@"{winsock}\{catalog}"))
            {
                var dll = r.GetString($@"{winsock}\{catalog}\{entry}", "LibraryPath");
                if (string.IsNullOrWhiteSpace(dll)) continue;
                string path = Environment.ExpandEnvironmentVariables(dll);
                if (Suspicion.IsInWindows(path) || dll.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)) continue;
                AddDllFinding(list, context, path, $"Provider di nomi Winsock: {Path.GetFileName(path)}", $@"{winsock}\{catalog}\{entry} [LibraryPath] = {dll}", "Risolve i nomi dei siti per ogni programma: può dirottarli.");
            }
        return list;
    }

    private static void AddClsidFinding(List<Finding> list, CheckContext context, string clsid, string source, string title, Severity baseline)
    {
        var r = context.Registry;
        string? dll = r.GetString($@"HKEY_CURRENT_USER\Software\Classes\CLSID\{clsid}\InprocServer32", "")
            ?? r.GetString($@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32", "")
            ?? r.GetString($@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{clsid}\InprocServer32", "");
        if (dll is null) return;
        string path = ComHijackCheck.Resolve(dll);
        if (Suspicion.IsInWindows(path)) return;
        AddDllFinding(list, context, path, $"{title}: {r.GetString($@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{clsid}", "") ?? clsid}", $"{source} → {dll}", "Viene caricata dentro Esplora risorse: vede ogni file che apri.", baseline);
    }

    private static void AddDllFinding(List<Finding> list, CheckContext context, string path, string title, string evidence, string why, Severity baseline = Severity.Warning)
    {
        var signature = File.Exists(path) ? context.Signatures.Check(path) : null;
        if (signature?.IsMicrosoft == true) return;
        bool unsigned = signature is null || signature.Status != SignatureStatus.Signed;
        bool badPlace = Suspicion.IsInDangerousFolder(path, context.UserProfile) || Suspicion.IsBareDataFolder(path, context.UserProfile) || Suspicion.IsHiddenFolder(path);
        var severity = unsigned || badPlace ? Severity.Danger : baseline;
        if (signature?.Publisher is not null && context.TrustedPublishers.Contains(signature.Publisher) && severity < Severity.Danger) return;
        list.Add(new Finding($"dll|{path}", Categories.Persistence, title,
            why + (unsigned ? " La libreria non è firmata." : signature?.Publisher is null ? "" : $" Firmata da «{signature.Publisher}».") + (badPlace ? " Sta in una cartella dove i programmi non vivono." : ""),
            severity)
        { Path = path, Evidence = [evidence, signature is null ? "File non trovato o non leggibile" : $"Firma: {signature.Status}{(signature.Publisher is null ? "" : " · " + signature.Publisher)}"], Publisher = signature?.Publisher,
          Action = unsigned ? FindingAction.DefenderScan : FindingAction.None });
    }
}
