namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Root certificates added to the stores: one non-public root lets whoever
/// holds its key read HTTPS traffic. Adware and "free antivirus" products
/// install one to inject ads into secure pages.
/// </summary>
public sealed class TrustedRootsCheck : IProtectionCheck
{
    public string Id => "trusted-roots";
    public string Title => "Certificati radice";

    /// <summary>Public CAs and vendors whose roots Windows ships or updates on its own.</summary>
    private static readonly string[] KnownIssuers =
    [
        "Microsoft", "DigiCert", "GlobalSign", "Sectigo", "COMODO", "Comodo", "Entrust", "Go Daddy", "GoDaddy", "Starfield", "ISRG", "Let's Encrypt", "Amazon",
        "Google Trust", "GTS", "Baltimore", "VeriSign", "Thawte", "GeoTrust", "Certum", "Actalis", "QuoVadis", "SwissSign", "T-TeleSec", "D-TRUST", "IdenTrust",
        "USERTrust", "AAA Certificate Services", "Buypass", "Hellenic", "HARICA", "e-Szigno", "Microsec", "TWCA", "SSL.com", "Apple", "Cisco", "Atos", "Autoridad",
        "Certigna", "CFCA", "emSign", "GDCA", "GLOBALTRUST", "Hongkong Post", "Izenpe", "NetLock", "OISTE", "SecureTrust", "Security Communication", "SECOM", "Telia",
        "TrustAsia", "Trustwave", "UCA", "vTrus", "XRamp", "ANF", "Camerfirma", "Chambers of Commerce", "Staat der Nederlanden", "Government", "Agence Nationale",
        "Autoridade", "Certinomis", "DST Root", "E-Tugra", "Firmaprofesional", "Hotspot 2.0", "NAVER", "Network Solutions", "Sonera", "Symantec", "TUBITAK", "Trustis",
        "WoSign", "Disig", "Certplus", "OpenTrust", "KEYNECTIS", "Visa", "MasterCard", "ePKI", "Chunghwa", "Japanese Government", "AffirmTrust", "AddTrust", "Equifax",
        "Entrust.net", "Cybertrust", "GlobalSign Root", "Digital Signature Trust", "SecureSign", "Class 3 Public", "Class 2 Primary", "Starfield Services", "Copyright (c) 1997 Microsoft",
        "Thawte Timestamping", "NO LIABILITY ACCEPTED", "VeriSign Time Stamping", "Microsoft Root", "Microsoft Authenticode", "Microsoft Timestamp", "www.digicert.com",
        "Intel", "NVIDIA", "Dell", "HP Inc", "Lenovo", "Hewlett", "AMD", "Realtek", "Qualcomm", "ASUS", "Acer", "Samsung", "LG Electronics", "Synaptics", "Logitech",
        "Fortinet", "Zscaler", "Cisco Umbrella", "Sophos", "Kaspersky", "ESET", "Bitdefender", "Avast", "AVG", "Norton", "McAfee", "Trend Micro", "F-Secure", "Malwarebytes",
    ];

    /// <summary>Debugging proxies and local development certificates: fine when the user put them there.</summary>
    private static readonly string[] DevTools = ["mkcert", "localhost", "Docker", "Charles", "Fiddler", "mitmproxy", "Burp", "Proxyman", "Postman", "ASP.NET Core", "dotnet", "Visual Studio"];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        foreach (var root in context.Certificates.Roots())
        {
            if (!root.IsSelfSigned) continue;
            string subject = Subject(root.Subject);
            bool known = KnownIssuers.Any(k => subject.Contains(k, StringComparison.OrdinalIgnoreCase));
            bool userStore = root.Store == "utente";
            // The user's store also lists the machine roots: a public CA there is normal.
            if (known) continue;
            bool devTool = DevTools.Any(k => subject.Contains(k, StringComparison.OrdinalIgnoreCase));
            bool recent = (context.Now - root.NotBefore).TotalDays < 3 * 365;
            if (!userStore && !recent && !devTool) continue; // old machine roots are Windows's own
            yield return new Finding($"root|{root.Thumbprint}", Categories.Configuration, $"Certificato radice fidato: {subject}",
                (userStore ? "Nel negozio dell'utente: nessun programma normale ne mette uno lì. " : "Aggiunto al computer di recente e non di una CA pubblica. ")
                + (devTool ? "Sembra uno strumento di sviluppo (proxy di debug): va bene se lo usi tu." : "Chi ha la sua chiave può leggere le connessioni sicure (banca compresa)."),
                devTool ? Severity.Info : Severity.Danger)
            { Evidence = [$"Soggetto: {root.Subject}", $"Negozio: {root.Store}", $"Valido dal {root.NotBefore:d}", $"Impronta: {root.Thumbprint}"], SettingsLink = null };
        }
    }

    internal static string Subject(string distinguished)
    {
        var cn = System.Text.RegularExpressions.Regex.Match(distinguished, @"CN=([^,]+)");
        return cn.Success ? cn.Groups[1].Value.Trim() : distinguished;
    }
}
