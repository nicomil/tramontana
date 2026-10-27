using System.Security.AccessControl;
using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Protection;

namespace WinCleaner.Tests;

public class QuarantineTests
{
    [Fact]
    public void PutLocksRestoresAndDeletes()
    {
        using var temp = new TempDir();
        var log = new OperationLog(temp.Sub("ops.log"));
        var quarantine = new Quarantine(temp.Dir("Quarantine"), log);
        string evilDir = temp.Dir(@"roots\AppData\Roaming\Evil");
        string agent = temp.File(@"roots\AppData\Roaming\Evil\agent.exe", 200);
        temp.File(@"roots\AppData\Roaming\Evil\data\config.json", 10);
        string root = temp.Sub("roots", "AppData", "Roaming");

        var record = quarantine.Put(evilDir, "Evil", "test", [root]);
        Assert.False(Directory.Exists(evilDir));
        Assert.Equal("Evil", record.StoredName);
        Assert.True(Directory.Exists(record.StoredPath));
        Assert.Single(quarantine.Records());
        string storedAgent = Path.Combine(record.StoredPath, "agent.exe");
        Assert.True(File.GetAttributes(storedAgent).HasFlag(FileAttributes.Hidden));
        Assert.Equal("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n", File.ReadAllText(storedAgent + ":Zone.Identifier"));
        var rules = new FileInfo(storedAgent).GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
        Assert.All(rules.Cast<FileSystemAccessRule>(), r => Assert.False(r.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile) && r.AccessControlType == AccessControlType.Allow));
        Assert.True(File.Exists(storedAgent)); // still readable by the owner

        // Something else took the place: restore refuses.
        Directory.CreateDirectory(evilDir);
        Assert.Throws<InvalidOperationException>(() => quarantine.Restore(record, [root]));
        Directory.Delete(evilDir);

        // Outside the allowed roots: refused before anything moves.
        Assert.Throws<InvalidOperationException>(() => quarantine.Restore(record, [temp.Sub("elsewhere")]));
        Assert.True(Directory.Exists(record.StoredPath));

        quarantine.Restore(record, [root]);
        Assert.True(File.Exists(agent));
        Assert.False(File.GetAttributes(agent).HasFlag(FileAttributes.Hidden));
        Assert.False(File.Exists(agent + ":Zone.Identifier"));
        Assert.Empty(quarantine.Records());
        Assert.False(Directory.Exists(record.StoredFolder));

        var again = quarantine.Put(agent, "agent", "test", [root]);
        quarantine.Delete(again);
        Assert.False(Directory.Exists(again.StoredFolder));
        Assert.Empty(quarantine.Records());
        Assert.Contains("quarantine\tput", File.ReadAllText(log.FilePath));
    }

    [Fact]
    public void PutRefusesOutsideRootsAndJunctions()
    {
        using var temp = new TempDir();
        var quarantine = new Quarantine(temp.Dir("Quarantine"), null);
        string precious = temp.File(@"outside\precious.txt");
        string root = temp.Dir("root");
        Assert.Throws<InvalidOperationException>(() => quarantine.Put(precious, "x", "r", [root]));
        // A junction inside the root: the item behind it is never moved.
        string link = temp.Sub("root", "link");
        TempDir.Junction(link, temp.Sub("outside"));
        Assert.Throws<InvalidOperationException>(() => quarantine.Put(Path.Combine(link, "precious.txt"), "x", "r", [root]));
        Assert.True(File.Exists(precious));
        // The junction itself can be quarantined as a link, without touching its target.
        var record = quarantine.Put(link, "link", "r", [root]);
        Assert.True(File.Exists(precious));
        Assert.True(new DirectoryInfo(record.StoredPath).Attributes.HasFlag(FileAttributes.ReparsePoint));
    }

    [Fact]
    public void ProtectionRegistryAllowListIsExact()
    {
        Assert.Null(ProtectionRegistry.Resolve(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger"));
        Assert.Equal("explorer.exe", ProtectionRegistry.Resolve(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"));
        Assert.Equal("", ProtectionRegistry.Resolve(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"));
        Assert.Null(ProtectionRegistry.Resolve(@"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "1"));
        Assert.Null(ProtectionRegistry.Resolve(@"HKCU\Software\Classes\CLSID\{AAAA}\TreatAs", ""));
        Assert.False(ProtectionRegistry.IsAllowed(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultUserName"));
        Assert.False(ProtectionRegistry.IsAllowed(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", "Start"));
        Assert.False(ProtectionRegistry.IsAllowed(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\extra", "Debugger"));
        Assert.True(ProtectionRegistry.NeedsAdmin(@"HKLM\SOFTWARE\x"));
        Assert.False(ProtectionRegistry.NeedsAdmin(@"HKCU\Software\x"));
    }

    [Fact]
    public void ProtectionRegistryApplyBacksUpAndRestoresOrDeletes()
    {
        string key = @"HKEY_CURRENT_USER\Software\Classes\CLSID\{WINCLEANER-TEST-" + Guid.NewGuid().ToString("N")[..8] + "}";
        try
        {
            using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(key["HKEY_CURRENT_USER\\".Length..] + @"\TreatAs")) k.SetValue("", "{BBBB}");
            var backup = ProtectionRegistry.Apply(key + @"\TreatAs", "", null);
            Assert.True(File.Exists(backup));
            Assert.Contains("TreatAs", File.ReadAllText(backup));
            using var after = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(key["HKEY_CURRENT_USER\\".Length..] + @"\TreatAs");
            Assert.Null(after?.GetValue(""));
            Assert.Throws<InvalidOperationException>(() => ProtectionRegistry.Apply(key, "Other", null));
            File.Delete(backup);
        }
        finally
        {
            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(key["HKEY_CURRENT_USER\\".Length..], throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public async Task HelperRefusesWrongProcessAndUnlistedValues()
    {
        var wrong = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.TerminateProcess, Number = Environment.ProcessId, Key = @"C:\nope.exe" }, CancellationToken.None);
        Assert.False(wrong.Ok);
        Assert.Contains("non è più", wrong.Error);
        var unlisted = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RemoveProtectionValue, Key = @"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", Name = "Start" }, CancellationToken.None);
        Assert.False(unlisted.Ok);
        var badExclusion = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RemoveDefenderExclusion, Name = "C:\\x'; Remove-Item C:\\" }, CancellationToken.None);
        Assert.False(badExclusion.Ok);
        var badId = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RestoreQuarantined, Name = "not-a-guid" }, CancellationToken.None);
        Assert.False(badId.Ok);
    }

    [Fact]
    public async Task EvidenceCollectionProducesTheSections()
    {
        var text = await EvidenceCollection.CollectAsync(CancellationToken.None);
        var evidence = SystemEvidence.Parse(text);
        foreach (var section in new[] { "defender-exclusions", "bitlocker", "wmi-subscriptions", "bits", "tpm", "processes", "security-log", "system-log" })
            Assert.NotNull(evidence[section]);
        Assert.Contains(evidence["processes"]!.Split('\n'), l => l.StartsWith(Environment.ProcessId + "|"));
    }
}

public class EndToEndTests
{
    /// <summary>The deep scan as the app runs it: real evidence from the helper code, fed to every check.</summary>
    [Fact]
    public async Task DeepScanWithRealEvidenceRunsEveryCheck()
    {
        var text = await EvidenceCollection.CollectAsync(CancellationToken.None);
        var evidence = SystemEvidence.Parse(text);
        var findings = ProtectionScanner.Run(new CheckContext { Evidence = evidence, Startup = [] }, ProtectionScanner.DefaultChecks());
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Reason)));
        Assert.Contains(findings, f => f.Category == WinCleaner.Modules.Protection.Categories.Defences);
        var report = ProtectionReport.Markdown(findings);
        Assert.Contains("## Riepilogo", report);
    }

    /// <summary>System quarantine through the helper service, round trip, on a folder under ProgramData (needs an administrator token).</summary>
    [Fact]
    public async Task HelperQuarantinesRestoresAndDeletesSystemItems()
    {
        if (!HelperService.IsElevated()) return;
        string folder = Path.Combine(KnownPaths.ProgramData, "WinCleanerTest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(folder);
        string file = Path.Combine(folder, "agent.exe");
        File.WriteAllBytes(file, [0x4D, 0x5A, 1, 2, 3]);
        QuarantineRecord? record = null;
        try
        {
            var put = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.Quarantine, Paths = [file], Name = "agent", Key = "test" }, CancellationToken.None);
            Assert.True(put.Ok, put.Error);
            var outcome = Assert.Single(put.Outcomes);
            Assert.Null(outcome.Error);
            Assert.False(File.Exists(file));
            var parts = outcome.Message!.Split('|');
            record = new Quarantine(Quarantine.SystemFolder, null).Records().Single(r => r.Id == Guid.ParseExact(parts[0], "N"));
            Assert.True(File.Exists(record.StoredPath));

            var restore = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RestoreQuarantined, Name = record.Id.ToString() }, CancellationToken.None);
            Assert.True(restore.Ok, restore.Error);
            Assert.True(File.Exists(file));
            Assert.DoesNotContain(new Quarantine(Quarantine.SystemFolder, null).Records(), r => r.Id == record.Id);

            var again = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.Quarantine, Paths = [file], Name = "agent", Key = "test" }, CancellationToken.None);
            Assert.True(again.Ok, again.Error);
            var id = Guid.ParseExact(again.Outcomes[0].Message!.Split('|')[0], "N");
            var delete = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.DeleteQuarantined, Name = id.ToString() }, CancellationToken.None);
            Assert.True(delete.Ok, delete.Error);
            Assert.DoesNotContain(new Quarantine(Quarantine.SystemFolder, null).Records(), r => r.Id == id);
            record = null;

            var blocked = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.Quarantine, Paths = [Path.Combine(Environment.SystemDirectory, "notepad.exe")] }, CancellationToken.None);
            Assert.NotNull(Assert.Single(blocked.Outcomes).Error);
        }
        finally
        {
            if (record is not null) try { new Quarantine(Quarantine.SystemFolder, null).Delete(record); } catch (Exception) { }
            try { Directory.Delete(folder, recursive: true); } catch (IOException) { }
        }
    }
}
