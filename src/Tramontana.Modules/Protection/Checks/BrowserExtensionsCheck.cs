using System.Text.Json;
using Tramontana.Core;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>Chromium extensions, judged by what the browser recorded about their origin, never by their manifest.</summary>
public sealed class BrowserExtensionsCheck : IProtectionCheck
{
    public string Id => "browser-extensions";
    public string Title => "Estensioni dei browser";

    public IEnumerable<Finding> Run(CheckContext context)
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

    /// <summary>Extensions the browsers install on their own (Docs Offline, Web Store payments, Media Router).</summary>
    private static readonly HashSet<string> DefaultExtensions =
        ["ghbmnnjooekpmoecnnnilnnbdlolhkhi", "nmmhkkegccagdldgiimedpiccmgmieda", "pkedcjkdefgpdelpbcmbmeomcjbeemfm", "mhjfbmdgcfjbbpaeojofohoefgiehjai"];

    /// <summary>
    /// Where an extension came from is read from what the browser recorded in
    /// the profile ("location", "from_webstore"), not from the extension's own
    /// manifest, which anyone can write.
    /// </summary>
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
                    var hostsSeen = new List<string>();
                    foreach (var key in new[] { "active_permissions", "granted_permissions" })
                    {
                        if (!s.TryGetProperty(key, out var perms)) continue;
                        foreach (var listName in new[] { "explicit_host", "scriptable_host" })
                            if (perms.TryGetProperty(listName, out var hosts) && hosts.ValueKind == JsonValueKind.Array)
                                foreach (var h in hosts.EnumerateArray())
                                {
                                    var host = h.GetString() ?? "";
                                    hostsSeen.Add(host);
                                    broad |= host is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*";
                                }
                    }

                    // Edge records store installs as internal without from_webstore.
                    bool storeLike = fromStore || defaultInstall || (browser.Id.StartsWith("edge") && location == 1);
                    (Severity, string)? verdict = location switch
                    {
                        2 or 3 or 6 => (Severity.Warning, "Installata da un altro programma, non da te dal negozio delle estensioni."),
                        4 or 8 => (Severity.Info, "Estensione caricata in modalità sviluppatore."),
                        7 or 9 => (Severity.Warning, "Imposta da un criterio (azienda, scuola o un programma installato): sui PC di casa è il trucco dell'adware."),
                        _ when !storeLike => (Severity.Warning, "Non viene dal negozio delle estensioni."),
                        _ when broad => (Severity.Info, "Può leggere e modificare i dati di tutti i siti che visiti."),
                        _ => null,
                    };
                    if (verdict is { } v)
                        findings.Add(new Finding($"ext|{browser.Id}|{Path.GetFileName(profile)}|{entry.Name}", Categories.Browser,
                            $"{name} ({browser.Name})", v.Item2, v.Item1)
                        {
                            Path = Path.Combine(profile, "Extensions", entry.Name),
                            Evidence = [$"ID: {entry.Name}", $"location: {location}", $"from_webstore: {fromStore}", .. hostsSeen.Distinct().Take(10).Select(h => "Sito: " + h)],
                        });
                }
            }
        }
        return findings;
    }
}
