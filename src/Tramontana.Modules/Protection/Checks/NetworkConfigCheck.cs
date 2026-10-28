using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>Where the PC's traffic goes: hosts file, proxy and automatic proxy script.</summary>
public sealed class NetworkConfigCheck : IProtectionCheck
{
    public string Id => "network";
    public string Title => "Rete";

    private static readonly string[] PublicSuffixes = ["com", "net", "org", "it", "eu", "de", "fr", "es", "uk", "io", "co", "app", "me", "info", "biz", "tv", "ch", "at", "nl", "be", "us", "ca", "au", "edu", "gov", "cloud", "ai", "xyz"];

    internal static bool LooksPublic(string name)
    {
        int dot = name.LastIndexOf('.');
        return dot > 0 && PublicSuffixes.Contains(name[(dot + 1)..].ToLowerInvariant());
    }

    public const string DnsQuery = "SELECT Description, DNSServerSearchOrder, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True";
    private static readonly HashSet<string> KnownResolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"];

    internal static bool IsPrivate(string address) =>
        address.StartsWith("10.") || address.StartsWith("192.168.") || address.StartsWith("127.") || address.StartsWith("fe80:") || address.StartsWith("fd") || address.StartsWith("fc")
        || address.StartsWith("169.254.") || (address.StartsWith("172.") && int.TryParse(address.Split('.').Skip(1).FirstOrDefault(), out var second) && second is >= 16 and <= 31);

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();

        // DNS servers that are neither the router nor a known public resolver.
        foreach (var adapter in context.Wmi.Query(@"root\cimv2", DnsQuery))
        {
            var servers = DefenderCheck.Strings(adapter.GetValueOrDefault("DNSServerSearchOrder"));
            var odd = servers.Where(s => !KnownResolvers.Contains(s) && !IsPrivate(s)).ToList();
            if (odd.Count == 0) continue;
            string name = adapter.GetValueOrDefault("Description") as string ?? "scheda di rete";
            list.Add(new Finding($"dns|{name}", Categories.Network, $"Server DNS insoliti su {name}: {string.Join(", ", odd)}",
                "Non sono né il router né un servizio DNS conosciuto: possono mandare i siti dove vogliono." + (adapter.GetValueOrDefault("DHCPEnabled") is false ? " Impostati a mano, non dal router." : ""),
                Severity.Warning)
            { SettingsLink = "ms-settings:network-status", Action = FindingAction.OpenSettings, Evidence = [.. servers.Select(s => "DNS: " + s)] });
        }

        // Inbound firewall rules that let unsigned programs in user folders accept connections.
        const string rules = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        foreach (var name in context.Registry.ValueNames(rules))
        {
            var rule = context.Registry.GetString(rules, name);
            if (rule is null || !rule.Contains("|Action=Allow|", StringComparison.OrdinalIgnoreCase) || !rule.Contains("|Dir=In|", StringComparison.OrdinalIgnoreCase) || rule.Contains("|Active=FALSE|", StringComparison.OrdinalIgnoreCase)) continue;
            var app = System.Text.RegularExpressions.Regex.Match(rule, @"\|App=([^|]+)\|");
            if (!app.Success) continue;
            string path = Environment.ExpandEnvironmentVariables(app.Groups[1].Value);
            if (Suspicion.IsInWindows(path) || PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFiles) || PathGuard.IsStrictlyInside(path, KnownPaths.ProgramFilesX86)) continue;
            if (!File.Exists(path)) continue;
            var signature = context.Signatures.Check(path);
            if (signature.Status == SignatureStatus.Signed && (signature.IsMicrosoft || (signature.Publisher is not null && context.TrustedPublishers.Contains(signature.Publisher)))) continue;
            bool unsigned = signature.Status != SignatureStatus.Signed;
            if (!unsigned && !Suspicion.IsInDangerousFolder(path, context.UserProfile)) continue;
            var ruleName = System.Text.RegularExpressions.Regex.Match(rule, @"\|Name=([^|]+)\|");
            list.Add(new Finding($"fwrule|{name}", Categories.Network, $"Il firewall lascia entrare {Path.GetFileName(path)}",
                (unsigned ? "Un programma senza firma" : "Un programma in una cartella temporanea") + " accetta connessioni dalla rete: tipico di backdoor e strumenti di controllo remoto.", Severity.Warning)
            { Path = path, Evidence = [$"Regola: {(ruleName.Success ? ruleName.Groups[1].Value : name)}", $"App: {path}", $"Firma: {signature.Status}"], Publisher = signature.Publisher, SettingsLink = "windowsdefender://network", Action = FindingAction.OpenSettings });
        }
        var text = CheckContext.Text(context.HostsFile);
        if (text is not null)
        {
            var entries = text.Split('\n').Select(l => l.Split('#')[0].Trim()).Where(l => l.Length > 0)
                .Select(l => l.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries)).Where(p => p.Length >= 2).ToList();
            var redirects = entries.Where(p => p[0] is not ("127.0.0.1" or "::1" or "0.0.0.0") && !p[1].Equals("localhost", StringComparison.OrdinalIgnoreCase)).ToList();
            var blocks = entries.Where(p => p[0] is "127.0.0.1" or "::1" or "0.0.0.0" && !p[1].Equals("localhost", StringComparison.OrdinalIgnoreCase) && p[1] != "broadcasthost").ToList();
            if (redirects.Count > 0)
            {
                bool real = redirects.Any(p => p.Skip(1).Any(LooksPublic));
                list.Add(new Finding("hosts-redirect", Categories.Network, $"Il file hosts manda {redirects.Count} nomi verso altri indirizzi",
                    real ? "Domini veri risolti su indirizzi scelti da qualcuno: possono dirottare siti e aggiornamenti."
                         : "Nomi locali o di prova risolti a mano: normale per chi sviluppa, da controllare altrimenti.",
                    real ? Severity.Danger : Severity.Warning)
                { Path = context.HostsFile, Evidence = [.. redirects.Take(30).Select(p => string.Join(' ', p))] });
            }
            if (blocks.Count > 0)
                list.Add(new Finding("hosts-block", Categories.Network, $"Il file hosts blocca {blocks.Count} nomi",
                    "Voci verso localhost: tipiche di un blocco della pubblicità, ma anche di malware che blocca gli antivirus e gli aggiornamenti.",
                    blocks.Any(p => p.Skip(1).Any(n => n.Contains("microsoft", StringComparison.OrdinalIgnoreCase) || n.Contains("windowsupdate", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("defender", StringComparison.OrdinalIgnoreCase) || n.Contains("avast", StringComparison.OrdinalIgnoreCase)
                        || n.Contains("kaspersky", StringComparison.OrdinalIgnoreCase) || n.Contains("malwarebytes", StringComparison.OrdinalIgnoreCase))) ? Severity.Danger : Severity.Info)
                { Path = context.HostsFile, Evidence = [.. blocks.Take(30).Select(p => string.Join(' ', p))] });
        }

        const string internet = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        if (context.Registry.GetInt(internet, "ProxyEnable") == 1)
        {
            var server = context.Registry.GetString(internet, "ProxyServer") ?? "?";
            list.Add(new Finding("proxy-on", Categories.Network, "Proxy attivo", $"Il traffico web passa da {server}. Va bene solo se l'hai impostato tu o la tua azienda.", Severity.Warning)
            { SettingsLink = "ms-settings:network-proxy", Action = FindingAction.OpenSettings, Evidence = [$"ProxyServer = {server}"] });
        }
        if (context.Registry.GetString(internet, "AutoConfigURL") is { Length: > 0 } pac)
            list.Add(new Finding("proxy-pac", Categories.Network, "Configurazione automatica del proxy", $"Uno script remoto decide da dove passa il traffico: {pac}.", Severity.Danger)
            { SettingsLink = "ms-settings:network-proxy", Action = FindingAction.OpenSettings, Evidence = [$"AutoConfigURL = {pac}"] });
        return list;
    }
}
