using System.Text.Json;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// The browser as adware leaves it: extensions forced by policy, home page,
/// start-up pages and search engine set by policy or in the profile, Firefox
/// side-loaded add-ons and enterprise policies on a home PC.
/// </summary>
public sealed class BrowserHijackCheck : IProtectionCheck
{
    public string Id => "browser-hijack";
    public string Title => "Dirottamento del browser";

    private static readonly string[] KnownSearchHosts = ["google.", "bing.com", "duckduckgo.com", "ecosia.org", "yahoo.com", "qwant.com", "startpage.com",
        "search.brave.com", "yandex.", "baidu.com", "kagi.com", "perplexity.ai", "you.com", "microsoft.com", "msn.com", "mozilla.org", "ask.com"];

    private static readonly (string Key, string Browser)[] PolicyRoots =
    [
        (@"SOFTWARE\Policies\Google\Chrome", "Google Chrome"),
        (@"SOFTWARE\Policies\Microsoft\Edge", "Microsoft Edge"),
        (@"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
        (@"SOFTWARE\Policies\Chromium", "Chromium"),
        (@"SOFTWARE\Policies\Vivaldi", "Vivaldi"),
        (@"SOFTWARE\Policies\Opera Software", "Opera"),
        (@"SOFTWARE\Policies\Mozilla\Firefox", "Firefox"),
    ];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();
        bool domainJoined = !string.IsNullOrEmpty(r.GetString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain"));
        var policyLevel = domainJoined ? Severity.Warning : Severity.Danger;
        string why = domainJoined ? "Il PC è in un dominio: può essere un criterio aziendale." : "Su un PC di casa nessuno imposta criteri: li scrive l'adware per non farsi togliere.";

        foreach (var hive in new[] { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER" })
            foreach (var (root, browser) in PolicyRoots)
            {
                string key = $@"{hive}\{root}";
                // Forced extensions.
                foreach (var listName in new[] { "ExtensionInstallForcelist", "ExtensionSettings" })
                {
                    var forced = r.ValueNames($@"{key}\{listName}").Select(n => r.GetString($@"{key}\{listName}", n) ?? "").Where(v => v.Length > 0).ToList();
                    if (listName == "ExtensionSettings") forced = [.. r.SubKeys($@"{key}\{listName}").Where(id => r.GetString($@"{key}\{listName}\{id}", "installation_mode") is "force_installed" or "normal_installed")];
                    foreach (var entry in forced)
                    {
                        string id = entry.Split(';')[0];
                        list.Add(new Finding($"policy-ext|{browser}|{id}", Categories.Browser, $"Estensione imposta da un criterio in {browser}",
                            $"L'estensione {id} è installata di forza e non si può togliere dal browser. {why}", policyLevel)
                        { Path = $@"{key}\{listName}", Evidence = [$@"{key}\{listName}: {entry}"], Action = FindingAction.RemoveRegistryValue,
                          Registry = new RegistryTargetInfo($@"{key}\{listName}", r.ValueNames($@"{key}\{listName}").FirstOrDefault(n => (r.GetString($@"{key}\{listName}", n) ?? "") == entry) ?? "") });
                    }
                }
                // Search, home page, start-up pages.
                foreach (var (value, title) in new[] { ("DefaultSearchProviderSearchURL", "motore di ricerca"), ("HomepageLocation", "pagina iniziale"), ("NewTabPageLocation", "pagina Nuova scheda") })
                {
                    var url = r.GetString(key, value);
                    if (url is null) continue;
                    string host = Host(url);
                    if (IsKnownSearch(host)) continue;
                    list.Add(new Finding($"policy|{browser}|{value}", Categories.Browser, $"{browser}: {title} imposta da un criterio",
                        $"{title[..1].ToUpperInvariant()}{title[1..]} forzata su {host}. {why}", policyLevel)
                    { Path = key, Evidence = [$"{key} [{value}] = {url}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo(key, value) });
                }
                var startup = r.ValueNames($@"{key}\RestoreOnStartupURLs").Select(n => r.GetString($@"{key}\RestoreOnStartupURLs", n) ?? "").Where(u => u.Length > 0 && !IsKnownSearch(Host(u))).ToList();
                if (startup.Count > 0)
                    list.Add(new Finding($"policy|{browser}|startup", Categories.Browser, $"{browser}: pagine di avvio imposte da un criterio",
                        $"All'avvio apre {startup.Count} pagine decise da un criterio. {why}", policyLevel)
                    { Path = $@"{key}\RestoreOnStartupURLs", Evidence = [.. startup.Take(10)] });
                // Firefox: a policies.json in the install folder does the same.
            }

        // Chromium profiles: what the user sees.
        foreach (var browser in BrowserCatalog.Chromium)
        {
            string? userData = KnownPaths.Expand(browser.UserData);
            if (userData is null || !Directory.Exists(userData)) continue;
            var profiles = browser.ProfileIsRoot ? [userData] : Directory.EnumerateDirectories(userData).Where(d => File.Exists(Path.Combine(d, "Preferences"))).ToList();
            foreach (var profile in profiles)
                list.AddRange(ChromiumProfile(browser.Name, profile));
        }

        // Firefox: policies.json next to the program, prefs and side-loaded add-ons in the profiles.
        foreach (var dir in new[] { Path.Combine(KnownPaths.ProgramFiles, "Mozilla Firefox"), Path.Combine(KnownPaths.ProgramFilesX86, "Mozilla Firefox") })
        {
            string policies = Path.Combine(dir, "distribution", "policies.json");
            var text = CheckContext.Text(policies);
            if (text is null) continue;
            list.Add(new Finding("firefox-policies", Categories.Browser, "Firefox: file di criteri aziendali presente",
                $"«{policies}» impone impostazioni ed estensioni. {why}", policyLevel) { Path = policies, Evidence = [text.Length > 600 ? text[..600] : text], Action = FindingAction.Quarantine });
        }
        foreach (var gecko in BrowserCatalog.Gecko)
        {
            string? roaming = KnownPaths.Expand(gecko.RoamingRoot);
            if (roaming is null) continue;
            string profiles = Path.Combine(roaming, "Profiles");
            if (!Directory.Exists(profiles)) continue;
            foreach (var profile in Directory.EnumerateDirectories(profiles))
            {
                foreach (var file in new[] { "user.js", "prefs.js" })
                {
                    var text = CheckContext.Text(Path.Combine(profile, file), 5_000_000);
                    if (text is null) continue;
                    var home = System.Text.RegularExpressions.Regex.Match(text, "\"browser\\.startup\\.homepage\",\\s*\"([^\"]+)\"");
                    if (home.Success && !IsKnownSearch(Host(home.Groups[1].Value)) && !home.Groups[1].Value.StartsWith("about:"))
                        list.Add(new Finding($"firefox|{Path.GetFileName(profile)}|homepage", Categories.Browser, $"{gecko.Name}: pagina iniziale {Host(home.Groups[1].Value)}",
                            file == "user.js" ? "Impostata da un file user.js, che nessun utente scrive a mano: tipico dell'adware." : "Pagina iniziale impostata su un sito insolito.",
                            file == "user.js" ? Severity.Danger : Severity.Warning) { Path = Path.Combine(profile, file), Evidence = [home.Value] });
                    if (file == "user.js")
                        list.Add(new Finding($"firefox|{Path.GetFileName(profile)}|userjs", Categories.Browser, $"{gecko.Name}: file user.js presente",
                            "Riapplica impostazioni a ogni avvio, sopra quelle scelte dall'utente. Nessun programma normale lo crea.", Severity.Warning)
                        { Path = Path.Combine(profile, file), Evidence = [.. text.Split('\n').Take(10).Select(l => l.Trim())], Action = FindingAction.Quarantine });
                }
                var extensions = CheckContext.Text(Path.Combine(profile, "extensions.json"), 10_000_000);
                if (extensions is null) continue;
                try
                {
                    using var doc = JsonDocument.Parse(extensions);
                    if (!doc.RootElement.TryGetProperty("addons", out var addons)) continue;
                    foreach (var addon in addons.EnumerateArray())
                    {
                        if (addon.TryGetProperty("type", out var t) && t.GetString() != "extension") continue;
                        if (addon.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.False) continue;
                        string location = addon.TryGetProperty("location", out var l) ? l.GetString() ?? "" : "";
                        if (location is "app-builtin" or "app-system-defaults" or "app-profile") continue;
                        string id = addon.TryGetProperty("id", out var i) ? i.GetString() ?? "?" : "?";
                        string name = addon.TryGetProperty("defaultLocale", out var dl) && dl.TryGetProperty("name", out var n) ? n.GetString() ?? id : id;
                        list.Add(new Finding($"firefox|{Path.GetFileName(profile)}|addon|{id}", Categories.Browser, $"{gecko.Name}: estensione installata dall'esterno: {name}",
                            $"Installata fuori dal profilo ({location}), cioè da un programma e non dall'utente.", Severity.Warning)
                        { Path = addon.TryGetProperty("path", out var p) ? p.GetString() : null, Evidence = [$"ID: {id}", $"location: {location}"] });
                    }
                }
                catch (JsonException) { }
            }
        }
        return list;
    }

    internal static IEnumerable<Finding> ChromiumProfile(string browser, string profile)
    {
        var findings = new List<Finding>();
        var text = CheckContext.Text(Path.Combine(profile, "Preferences"), 20_000_000);
        if (text is null) return findings;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text); } catch (JsonException) { return findings; }
        using (doc)
        {
            var root = doc.RootElement;
            string prefix = $"{browser}/{Path.GetFileName(profile)}";
            if (root.TryGetProperty("homepage", out var home) && home.ValueKind == JsonValueKind.String
                && !(root.TryGetProperty("homepage_is_newtabpage", out var ntp) && ntp.ValueKind == JsonValueKind.True)
                && !IsKnownSearch(Host(home.GetString()!)))
                findings.Add(new Finding($"hijack|{prefix}|homepage", Categories.Browser, $"{browser}: pagina iniziale", $"Pagina iniziale impostata su {Host(home.GetString()!)}.", Severity.Warning)
                { Path = Path.Combine(profile, "Preferences"), Evidence = [$"homepage = {home.GetString()}"] });
            if (root.TryGetProperty("session", out var session) && session.TryGetProperty("restore_on_startup", out var restore) && restore.TryGetInt32(out var mode) && mode == 4
                && session.TryGetProperty("startup_urls", out var urls) && urls.ValueKind == JsonValueKind.Array)
            {
                var odd = urls.EnumerateArray().Select(u => u.GetString() ?? "").Where(u => u.Length > 0 && !IsKnownSearch(Host(u))).ToList();
                if (odd.Count > 0)
                    findings.Add(new Finding($"hijack|{prefix}|startup", Categories.Browser, $"{browser}: pagine di avvio", $"All'avvio apre {odd.Count} pagine impostate da qualcuno.", Severity.Warning)
                    { Path = Path.Combine(profile, "Preferences"), Evidence = [.. odd.Take(10).Select(u => "startup_urls: " + u)] });
            }
            if (root.TryGetProperty("default_search_provider_data", out var dsp) && dsp.TryGetProperty("template_url_data", out var data)
                && data.TryGetProperty("url", out var url) && url.ValueKind == JsonValueKind.String && !IsKnownSearch(Host(url.GetString()!.Replace("{searchTerms}", "x"))))
                findings.Add(new Finding($"hijack|{prefix}|search", Categories.Browser, $"{browser}: motore di ricerca",
                    $"Le ricerche passano da {Host(url.GetString()!.Replace("{searchTerms}", "x"))} invece che da un motore conosciuto.", Severity.Danger)
                { Path = Path.Combine(profile, "Preferences"), Evidence = [$"Nome: {(data.TryGetProperty("short_name", out var sn) ? sn.GetString() : "?")}", $"URL: {url.GetString()}"] });
        }
        return findings;
    }

    internal static string Host(string url)
    {
        try { return new Uri(url.Contains("://") ? url : "http://" + url).Host; }
        catch (UriFormatException) { return url; }
    }

    internal static bool IsKnownSearch(string host)
    {
        string lower = host.ToLowerInvariant();
        return lower.Length == 0 || lower == "localhost" || KnownSearchHosts.Any(k => lower == k.TrimEnd('.') || lower.Contains(k) || lower.EndsWith("." + k.TrimEnd('.')));
    }
}
