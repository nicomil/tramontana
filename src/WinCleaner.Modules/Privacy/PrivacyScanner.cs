using System.Diagnostics;
using System.Xml.Linq;
using Microsoft.Win32;
using WinCleaner.Core;

namespace WinCleaner.Modules.Privacy;

public enum PrivacyKind { History, Cookies, Downloads, Autofill, Passwords, Sessions, RecentFiles, JumpLists, ExplorerHistory, Clipboard, WiFi }

public static class PrivacyKinds
{
    public static string Title(this PrivacyKind kind) => kind switch
    {
        PrivacyKind.History => "Cronologia",
        PrivacyKind.Cookies => "Cookie",
        PrivacyKind.Downloads => "Cronologia download",
        PrivacyKind.Autofill => "Dati dei moduli",
        PrivacyKind.Passwords => "Password salvate",
        PrivacyKind.Sessions => "Schede dell'ultima sessione",
        PrivacyKind.RecentFiles => "File recenti",
        PrivacyKind.JumpLists => "Elenchi di collegamenti (Jump List)",
        PrivacyKind.ExplorerHistory => "Ricerche, percorsi ed Esegui",
        PrivacyKind.Clipboard => "Appunti",
        PrivacyKind.WiFi => "Rete Wi‑Fi salvata",
        _ => kind.ToString(),
    };
}

/// <summary>How an item is cleaned.</summary>
public abstract record PrivacyAction
{
    /// <summary>Rows deleted with SQL (then VACUUM), after a backup copy goes to the Recycle Bin.</summary>
    public sealed record Sql(string Database, string[] Statements) : PrivacyAction;
    /// <summary>Files moved to the Recycle Bin.</summary>
    public sealed record Files(string[] Paths) : PrivacyAction;
    /// <summary>Registry keys or values, exported to .reg before deletion.</summary>
    public sealed record Registry(RegistryTarget[] Targets) : PrivacyAction;
    public sealed record Clipboard : PrivacyAction;
    /// <summary>A saved Wi‑Fi profile (needs administrator rights).</summary>
    public sealed record WiFi(string Profile) : PrivacyAction;
}

/// <summary>One row of the Privacy screen: e.g. "Chrome, profile Default, cookies: 1240".</summary>
public sealed record PrivacyItem(string Id, string Owner, string? Profile, PrivacyKind Kind, long Count, PrivacyAction Action, string[] Processes)
{
    /// <summary>Saved passwords, form data, jump lists and Wi‑Fi networks are never preselected.</summary>
    public bool AutoSelect => Kind is not (PrivacyKind.Passwords or PrivacyKind.Autofill or PrivacyKind.JumpLists or PrivacyKind.WiFi);
    public bool NeedsAdmin => Action is PrivacyAction.WiFi;
}

/// <summary>An app that used the camera, microphone or location (read only).</summary>
public sealed record CapabilityUse(string Capability, string App, DateTime? LastUsedUtc, bool InUse);

/// <summary>Finds browser and Windows traces, and cleans them.</summary>
public static class PrivacyScanner
{
    public static List<PrivacyItem> Scan()
    {
        var items = new List<PrivacyItem>();
        foreach (var browser in BrowserCatalog.Chromium) items.AddRange(Chromium(browser));
        foreach (var browser in BrowserCatalog.Gecko.Where(g => g.Id != "thunderbird")) items.AddRange(Gecko(browser));
        items.AddRange(WindowsTraces());
        items.AddRange(WiFiProfiles());
        return items;
    }

    private static IEnumerable<string> ChromiumProfiles(string userData)
    {
        if (!Directory.Exists(userData)) yield break;
        foreach (var dir in Directory.EnumerateDirectories(userData))
        {
            string name = Path.GetFileName(dir);
            if ((name == "Default" || name.StartsWith("Profile ", StringComparison.Ordinal) || name == "Guest Profile")
                && File.Exists(Path.Combine(dir, "Preferences")))
                yield return dir;
        }
    }

    private static IEnumerable<PrivacyItem> Chromium(ChromiumBrowser browser)
    {
        string? userData = KnownPaths.Expand(browser.UserData);
        if (userData is null) yield break;
        var profiles = browser.ProfileIsRoot ? (Directory.Exists(userData) ? [userData] : []) : ChromiumProfiles(userData).ToList();
        foreach (var dir in profiles)
        {
            string profile = browser.ProfileIsRoot ? "Default" : Path.GetFileName(dir);
            var owner = (browser.Name, profile, browser.Processes);
            foreach (var item in SqlItems(owner, Path.Combine(dir, "History"),
            [
                (PrivacyKind.History, "urls", ["DELETE FROM visits", "DELETE FROM urls", "DELETE FROM keyword_search_terms",
                                              "DELETE FROM segments", "DELETE FROM segment_usage", "DELETE FROM visit_source"]),
                (PrivacyKind.Downloads, "downloads", ["DELETE FROM downloads", "DELETE FROM downloads_url_chains"]),
            ])) yield return item;
            foreach (var cookies in new[] { Path.Combine(dir, "Network", "Cookies"), Path.Combine(dir, "Cookies") })
                foreach (var item in SqlItems(owner, cookies, [(PrivacyKind.Cookies, "cookies", ["DELETE FROM cookies"])])) yield return item;
            foreach (var item in SqlItems(owner, Path.Combine(dir, "Web Data"), [(PrivacyKind.Autofill, "autofill", ["DELETE FROM autofill"])])) yield return item;
            foreach (var item in SqlItems(owner, Path.Combine(dir, "Login Data"), [(PrivacyKind.Passwords, "logins", ["DELETE FROM logins"])])) yield return item;
            var sessions = Path.Combine(dir, "Sessions");
            if (Directory.Exists(sessions))
            {
                var files = Directory.GetFiles(sessions);
                if (files.Length > 0) yield return Item(owner, PrivacyKind.Sessions, files.Length, new PrivacyAction.Files(files));
            }
        }
    }

    private static IEnumerable<PrivacyItem> Gecko(GeckoBrowser browser)
    {
        string? roaming = KnownPaths.Expand(browser.RoamingRoot);
        if (roaming is null) yield break;
        string profilesDir = Path.Combine(roaming, "Profiles");
        if (!Directory.Exists(profilesDir)) yield break;
        foreach (var dir in Directory.EnumerateDirectories(profilesDir))
        {
            var owner = (browser.Name, Path.GetFileName(dir), browser.Processes);
            // Bookmarked places stay, the rest of the history goes.
            foreach (var item in SqlItems(owner, Path.Combine(dir, "places.sqlite"),
            [
                (PrivacyKind.History, "moz_historyvisits", ["DELETE FROM moz_historyvisits", "DELETE FROM moz_inputhistory",
                    "DELETE FROM moz_places WHERE id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL) AND id NOT IN (SELECT place_id FROM moz_annos)"]),
            ])) yield return item;
            foreach (var item in SqlItems(owner, Path.Combine(dir, "cookies.sqlite"), [(PrivacyKind.Cookies, "moz_cookies", ["DELETE FROM moz_cookies"])])) yield return item;
            foreach (var item in SqlItems(owner, Path.Combine(dir, "formhistory.sqlite"), [(PrivacyKind.Autofill, "moz_formhistory", ["DELETE FROM moz_formhistory"])])) yield return item;
            var logins = Path.Combine(dir, "logins.json");
            if (File.Exists(logins))
            {
                int count = CountJsonArray(logins, "logins");
                if (count > 0) yield return Item(owner, PrivacyKind.Passwords, count, new PrivacyAction.Files([logins]));
            }
            var sessionFiles = new[] { Path.Combine(dir, "sessionstore.jsonlz4") }
                .Concat(Directory.Exists(Path.Combine(dir, "sessionstore-backups")) ? Directory.GetFiles(Path.Combine(dir, "sessionstore-backups")) : [])
                .Where(File.Exists).ToArray();
            if (sessionFiles.Length > 0) yield return Item(owner, PrivacyKind.Sessions, sessionFiles.Length, new PrivacyAction.Files(sessionFiles));
        }
    }

    private static int CountJsonArray(string file, string property)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(file));
            return doc.RootElement.TryGetProperty(property, out var array) ? array.GetArrayLength() : 0;
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException) { return 0; }
    }

    private static IEnumerable<PrivacyItem> WindowsTraces()
    {
        var owner = ("Windows", (string?)null, Array.Empty<string>());
        var recent = KnownPaths.Recent;
        if (Directory.Exists(recent))
        {
            var links = Directory.GetFiles(recent, "*.lnk");
            if (links.Length > 0) yield return Item(owner, PrivacyKind.RecentFiles, links.Length, new PrivacyAction.Files(links));
            var jump = new[] { "AutomaticDestinations", "CustomDestinations" }
                .Select(d => Path.Combine(recent, d)).Where(Directory.Exists)
                .SelectMany(Directory.GetFiles).ToArray();
            if (jump.Length > 0) yield return Item(owner, PrivacyKind.JumpLists, jump.Length, new PrivacyAction.Files(jump));
        }

        var explorer = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer";
        var targets = new List<RegistryTarget>();
        long count = 0;
        foreach (var sub in new[] { "RecentDocs", "RunMRU", "TypedPaths", "WordWheelQuery", @"ComDlg32\OpenSavePidlMRU", @"ComDlg32\LastVisitedPidlMRU" })
        {
            string path = $@"{explorer}\{sub}";
            using var key = RegistryCleaner.Open(path, writable: false);
            if (key is null) continue;
            int entries = key.ValueCount + key.SubKeyCount;
            if (entries == 0) continue;
            count += entries;
            // Values of the list itself, and its sub-lists (RecentDocs\.txt…).
            foreach (var value in key.GetValueNames()) targets.Add(new RegistryTarget(path, value));
            foreach (var child in key.GetSubKeyNames()) targets.Add(new RegistryTarget($@"{path}\{child}"));
        }
        if (targets.Count > 0) yield return Item(owner, PrivacyKind.ExplorerHistory, count, new PrivacyAction.Registry([.. targets]));
        yield return Item(owner, PrivacyKind.Clipboard, 1, new PrivacyAction.Clipboard());
    }

    /// <summary>Saved Wi‑Fi profiles, from "netsh wlan export" (XML, any display language).</summary>
    public static IEnumerable<PrivacyItem> WiFiProfiles()
    {
        string folder = Path.Combine(Path.GetTempPath(), "wincleaner-wlan-" + Guid.NewGuid().ToString("N"));
        var names = new List<string>();
        try
        {
            Directory.CreateDirectory(folder);
            var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"))
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in new[] { "wlan", "export", "profile", $"folder={folder}" }) info.ArgumentList.Add(a);
            ProcessEnvironment.Sanitize(info);
            using (var p = Process.Start(info)!) { p.StandardOutput.ReadToEnd(); p.WaitForExit(15_000); }
            foreach (var file in Directory.GetFiles(folder, "*.xml"))
            {
                try
                {
                    var name = XDocument.Load(file).Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "name")?.Value;
                    if (!string.IsNullOrWhiteSpace(name)) names.Add(name);
                }
                catch (System.Xml.XmlException) { }
            }
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException) { }
        finally
        {
            // The export holds no keys (no key=clear), but nothing is left behind.
            try { Directory.Delete(folder, recursive: true); } catch (IOException) { }
        }
        foreach (var name in names.Distinct())
            yield return new PrivacyItem($"wifi|{name}", "Wi‑Fi", name, PrivacyKind.WiFi, 1, new PrivacyAction.WiFi(name), []);
    }

    private static IEnumerable<PrivacyItem> SqlItems((string Name, string? Profile, string[] Processes) owner, string db,
        (PrivacyKind Kind, string Table, string[] Statements)[] specs)
    {
        if (!File.Exists(db)) yield break;
        using var reader = SqliteDb.OpenReadOnly(db);
        if (reader is null) yield break;
        var found = new List<PrivacyItem>();
        foreach (var (kind, table, statements) in specs)
        {
            if (reader.Count(table) is { } count && count > 0)
                found.Add(Item(owner, kind, count, new PrivacyAction.Sql(db, statements)));
        }
        foreach (var item in found) yield return item;
    }

    private static PrivacyItem Item((string Name, string? Profile, string[] Processes) owner, PrivacyKind kind, long count, PrivacyAction action) =>
        new($"{owner.Name}|{owner.Profile}|{kind}|{(action is PrivacyAction.Sql s ? Path.GetFileName(s.Database) : action.GetType().Name)}",
            owner.Name, owner.Profile, kind, count, action, owner.Processes);

    /// <summary>Apps that used the camera, microphone or location, from the consent store (read only).</summary>
    public static List<CapabilityUse> CapabilityUses()
    {
        var result = new List<CapabilityUse>();
        var names = new Dictionary<string, string> { ["webcam"] = "Fotocamera", ["microphone"] = "Microfono", ["location"] = "Posizione" };
        foreach (var (capability, title) in names)
        {
            string path = $@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}";
            using var root = Registry.CurrentUser.OpenSubKey(path);
            if (root is null) continue;
            void Read(RegistryKey key, string app)
            {
                long start = key.GetValue("LastUsedTimeStart") is long s ? s : 0;
                long stop = key.GetValue("LastUsedTimeStop") is long t ? t : 0;
                if (start == 0) return;
                result.Add(new CapabilityUse(title, app, DateTime.FromFileTimeUtc(start), stop == 0 || stop < start));
            }
            foreach (var app in root.GetSubKeyNames().Where(n => n != "NonPackaged"))
            {
                using var key = root.OpenSubKey(app);
                if (key is not null) Read(key, app.Split('_')[0]);
            }
            using var nonPackaged = root.OpenSubKey("NonPackaged");
            foreach (var app in nonPackaged?.GetSubKeyNames() ?? [])
            {
                using var key = nonPackaged!.OpenSubKey(app);
                if (key is not null) Read(key, Path.GetFileName(app.Replace('#', '\\')));
            }
        }
        return result.OrderByDescending(r => r.LastUsedUtc).ToList();
    }
}
