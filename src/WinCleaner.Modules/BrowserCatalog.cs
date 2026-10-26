using WinCleaner.Core;

namespace WinCleaner.Modules;

/// <summary>A Chromium-based browser: where its profiles live and how its process is named.</summary>
public sealed record ChromiumBrowser(string Id, string Name, string UserData, string[] Processes)
{
    /// <summary>Opera keeps the profile in the folder itself and the caches under %LOCALAPPDATA%.</summary>
    public string? CacheRoot { get; init; }
    public bool ProfileIsRoot { get; init; }
}

/// <summary>A Gecko-based browser or mail client (Firefox and its forks, Thunderbird).</summary>
public sealed record GeckoBrowser(string Id, string Name, string RoamingRoot, string LocalRoot, string[] Processes);

/// <summary>The browsers the app knows, used for caches (system junk) and privacy items.</summary>
public static class BrowserCatalog
{
    public static readonly IReadOnlyList<ChromiumBrowser> Chromium =
    [
        new("chrome", "Google Chrome", @"%LOCALAPPDATA%\Google\Chrome\User Data", ["chrome"]),
        new("chrome-beta", "Google Chrome Beta", @"%LOCALAPPDATA%\Google\Chrome Beta\User Data", ["chrome"]),
        new("chrome-canary", "Google Chrome Canary", @"%LOCALAPPDATA%\Google\Chrome SxS\User Data", ["chrome"]),
        new("edge", "Microsoft Edge", @"%LOCALAPPDATA%\Microsoft\Edge\User Data", ["msedge"]),
        new("edge-beta", "Microsoft Edge Beta", @"%LOCALAPPDATA%\Microsoft\Edge Beta\User Data", ["msedge"]),
        new("edge-dev", "Microsoft Edge Dev", @"%LOCALAPPDATA%\Microsoft\Edge Dev\User Data", ["msedge"]),
        new("brave", "Brave", @"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data", ["brave"]),
        new("vivaldi", "Vivaldi", @"%LOCALAPPDATA%\Vivaldi\User Data", ["vivaldi"]),
        new("chromium", "Chromium", @"%LOCALAPPDATA%\Chromium\User Data", ["chrome", "chromium"]),
        new("arc", "Arc", @"%LOCALAPPDATA%\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data", ["Arc"]),
        new("opera", "Opera", @"%APPDATA%\Opera Software\Opera Stable", ["opera"])
            { ProfileIsRoot = true, CacheRoot = @"%LOCALAPPDATA%\Opera Software\Opera Stable" },
        new("opera-gx", "Opera GX", @"%APPDATA%\Opera Software\Opera GX Stable", ["opera"])
            { ProfileIsRoot = true, CacheRoot = @"%LOCALAPPDATA%\Opera Software\Opera GX Stable" },
    ];

    public static readonly IReadOnlyList<GeckoBrowser> Gecko =
    [
        new("firefox", "Firefox", @"%APPDATA%\Mozilla\Firefox", @"%LOCALAPPDATA%\Mozilla\Firefox", ["firefox"]),
        new("librewolf", "LibreWolf", @"%APPDATA%\librewolf", @"%LOCALAPPDATA%\librewolf", ["librewolf"]),
        new("waterfox", "Waterfox", @"%APPDATA%\Waterfox", @"%LOCALAPPDATA%\Waterfox", ["waterfox"]),
        new("zen", "Zen Browser", @"%APPDATA%\zen", @"%LOCALAPPDATA%\zen", ["zen"]),
        new("thunderbird", "Thunderbird", @"%APPDATA%\Thunderbird", @"%LOCALAPPDATA%\Thunderbird", ["thunderbird"]),
    ];

    private static readonly string[] ProfileCaches =
        ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "Media Cache"];

    private static readonly string[] UserDataCaches =
        ["ShaderCache", "GrShaderCache", "GraphiteDawnCache", @"Crashpad\reports", "BrowserMetrics"];

    /// <summary>Cache rules for every known browser (they are skipped while the browser runs).</summary>
    public static IEnumerable<CleaningRule> CacheRules()
    {
        foreach (var b in Chromium)
        {
            var profileRoots = b.ProfileIsRoot
                ? new[] { b.CacheRoot!, b.CacheRoot + @"\*", b.UserData }
                : new[] { b.UserData + @"\*" };
            yield return new CleaningRule
            {
                Id = $"browser-{b.Id}-cache",
                Group = "browsers",
                Category = $"browser-{b.Id}",
                Title = $"Cache di {b.Name}",
                Description = "Copie di pagine, immagini e script: il browser le riscarica quando servono. Si chiude il browser per pulirla.",
                Paths = [.. profileRoots.SelectMany(r => ProfileCaches.Select(c => $@"{r}\{c}")),
                         .. (b.ProfileIsRoot ? Enumerable.Empty<string>() : UserDataCaches.Select(c => $@"{b.UserData}\{c}"))],
                Target = RuleTarget.Itself,
                Processes = b.Processes,
            };
            yield return new CleaningRule
            {
                Id = $"browser-{b.Id}-sw",
                Group = "browsers",
                Category = $"browser-{b.Id}-sw",
                Title = $"Dati offline dei siti in {b.Name}",
                Description = "Cache dei Service Worker: alcune app web funzioneranno offline solo dopo averle riaperte.",
                Paths = [.. profileRoots.SelectMany(r => new[] { $@"{r}\Service Worker\CacheStorage", $@"{r}\Service Worker\ScriptCache" })],
                Target = RuleTarget.Itself,
                Risk = RiskLevel.Medium,
                AutoSelect = false,
                Processes = b.Processes,
            };
        }

        foreach (var g in Gecko)
        {
            yield return new CleaningRule
            {
                Id = $"browser-{g.Id}-cache",
                Group = "browsers",
                Category = $"browser-{g.Id}",
                Title = $"Cache di {g.Name}",
                Description = "Copie di pagine e immagini, miniature e cache di avvio.",
                Paths =
                [
                    $@"{g.LocalRoot}\Profiles\*\cache2",
                    $@"{g.LocalRoot}\Profiles\*\startupCache",
                    $@"{g.LocalRoot}\Profiles\*\thumbnails",
                    $@"{g.LocalRoot}\Profiles\*\jumpListCache",
                    $@"{g.LocalRoot}\Profiles\*\OfflineCache",
                    $@"{g.RoamingRoot}\Profiles\*\shader-cache",
                ],
                Target = RuleTarget.Itself,
                Processes = g.Processes,
            };
            yield return new CleaningRule
            {
                Id = $"browser-{g.Id}-crashes",
                Group = "browsers",
                Category = $"browser-{g.Id}",
                Title = $"Cache di {g.Name}",
                Paths = [$@"{g.RoamingRoot}\Crash Reports\submitted", $@"{g.RoamingRoot}\Crash Reports\pending"],
                Processes = g.Processes,
            };
        }
    }
}
