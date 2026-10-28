using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Tramontana.Core;
using Tramontana.Modules.Helper;
using Tramontana.Modules.Protection;

namespace Tramontana.Tests;

/// <summary>The fixes of the security review (docs/security-review.md): each one has a test that would have failed before.</summary>
public class HardeningTests
{
    [Fact]
    public void SecureFolderRefusesJunctionsAndTightensLooseFolders()
    {
        using var temp = new TempDir();
        // A junction where the folder should be: refused.
        string target = temp.Dir("target");
        string link = temp.Sub("link");
        TempDir.Junction(link, target);
        Assert.Throws<UnauthorizedAccessException>(() => SecureFolder.Verify(link));

        if (!HelperService.IsElevated()) return;
        // A folder of ours with an inherited (loose) DACL is tightened; a user-writable rule disappears.
        string loose = temp.Dir("loose");
        var created = SecureFolder.Ensure(temp.Path, "loose");
        Assert.Equal(KnownPaths.Long(loose), created);
        var security = new DirectoryInfo(loose).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        Assert.True(security.AreAccessRulesProtected);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        Assert.DoesNotContain(security.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), r => r.IdentityReference == users);
        // Created from scratch: administrators only.
        string fresh = SecureFolder.Ensure(temp.Path, "fresh", "inner");
        Assert.True(Directory.Exists(fresh));
        Assert.True(SecureFolder.IsStrict(new DirectoryInfo(fresh).GetAccessControl(AccessControlSections.Access)));
    }

    [Fact]
    public void QuarantineIgnoresRecordsThatPointElsewhere()
    {
        using var temp = new TempDir();
        var quarantine = new Quarantine(temp.Dir("Quarantine"), new OperationLog(temp.Sub("ops.log")));
        var id = Guid.NewGuid();
        // A planted record whose stored folder is outside the quarantine, or whose name is a path.
        var planted = new QuarantineRecord(id, "x", @"C:\Windows\System32\evil.dll", "r", DateTime.Now, temp.Dir("elsewhere"), "evil.dll", true);
        Assert.False(quarantine.IsWellFormed(planted));
        var traversal = new QuarantineRecord(id, "x", @"C:\Users\x\a.exe", "r", DateTime.Now, Path.Combine(quarantine.Folder, id.ToString("N")), @"..\..\evil.dll", false);
        Assert.False(quarantine.IsWellFormed(traversal));
        Assert.Throws<InvalidOperationException>(() => quarantine.Restore(planted, [@"C:\"]));
        Assert.Throws<InvalidOperationException>(() => quarantine.Delete(planted));
        // Written to the index, it is simply not listed.
        File.WriteAllText(Path.Combine(quarantine.Folder, "index.json"), System.Text.Json.JsonSerializer.Serialize(new[] { planted }));
        Assert.Empty(quarantine.Records());
    }

    [Fact]
    public void QuarantineRestoreNeverFollowsAJunctionToTheDestination()
    {
        using var temp = new TempDir();
        var quarantine = new Quarantine(temp.Dir("Quarantine"), new OperationLog(temp.Sub("ops.log")));
        string root = temp.Dir("root");
        string file = temp.File(@"root\app\agent.exe");
        var record = quarantine.Put(file, "agent", "test", [root]);
        // While it was away, the folder became a junction to somewhere else.
        Directory.Delete(temp.Sub("root", "app"));
        string outside = temp.Dir("outside");
        TempDir.Junction(temp.Sub("root", "app"), outside);
        Assert.Throws<ReparsePointException>(() => quarantine.Restore(record, [root]));
        Assert.Empty(Directory.GetFiles(outside));
        Assert.True(File.Exists(record.StoredPath));
    }

    [Fact]
    public void HelperServesOnlyTramontanaFromItsOwnFolder()
    {
        string helperDir = @"C:\Program Files\Tramontana";
        Assert.NotNull(HelperIdentity.Objection(null, helperDir, null, true));
        Assert.NotNull(HelperIdentity.Objection(@"C:\Users\x\evil\Tramontana.exe", helperDir, null, true));
        Assert.NotNull(HelperIdentity.Objection(@"C:\Program Files\Tramontana\other.exe", helperDir, null, true));
        Assert.NotNull(HelperIdentity.Objection(@"C:\Program Files\Tramontana\Tramontana.exe", helperDir, null, false));
        Assert.Null(HelperIdentity.Objection(@"C:\Program Files\Tramontana\Tramontana.exe", helperDir, null, true));
        // With a published hash, the dll next to the caller must match it.
        using var temp = new TempDir();
        string app = temp.File("Tramontana.exe");
        temp.File("Tramontana.dll", 300);
        string hash = PipeSecurityChecks.Sha256(temp.Sub("Tramontana.dll"));
        Assert.Null(HelperIdentity.Objection(app, temp.Path, hash, true));
        Assert.NotNull(HelperIdentity.Objection(app, temp.Path, "00" + hash[2..], true));
        Assert.NotNull(HelperIdentity.Objection(temp.File("trcli.exe"), temp.Path, hash, true));
    }

    [Fact]
    public void ToolsStartWithoutRuntimeHooksOrUserModules()
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe")) { UseShellExecute = false };
        info.Environment["COR_ENABLE_PROFILING"] = "1";
        info.Environment["CORECLR_PROFILER_PATH"] = @"C:\evil.dll";
        info.Environment["DOTNET_STARTUP_HOOKS"] = @"C:\evil.dll";
        info.Environment["COMPlus_Foo"] = "1";
        info.Environment["PSModulePath"] = @"C:\Users\x\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules";
        ProcessEnvironment.Sanitize(info);
        Assert.DoesNotContain(info.Environment.Keys, k => k.StartsWith("COR", StringComparison.OrdinalIgnoreCase) || k.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) || k.StartsWith("COMPlus", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("Users", info.Environment["PSModulePath"]);
        Assert.StartsWith(Environment.SystemDirectory, info.Environment["PATH"], StringComparison.OrdinalIgnoreCase);
        Assert.Throws<ArgumentException>(() => ProcessEnvironment.Sanitize(new ProcessStartInfo("x") { UseShellExecute = true }));
    }

    [Fact]
    public async Task HelperRefusesOddNamesForDefenderAndWmi()
    {
        // Typographic quotes used to escape a PowerShell literal: no longer a string problem, but still refused as "not present".
        var smart = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RemoveDefenderExclusion, Name = "C:\\x\u2019; Start-Process calc; \u2018" }, CancellationToken.None);
        Assert.False(smart.Ok);
        Assert.False(HelperService.IsPlainValue("a\nb"));
        Assert.False(HelperService.IsPlainValue(""));
        Assert.True(HelperService.IsPlainValue(@"C:\Program Files\App"));
        var wmi = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.RemoveWmiSubscription, Name = "Tramontana-nonexistent-" + Guid.NewGuid().ToString("N") }, CancellationToken.None);
        Assert.False(wmi.Ok);
        Assert.Equal("__EventFilter", EvidenceCollection.RefName("__EventFilter"));
        Assert.Equal("X", EvidenceCollection.RefName("__EventFilter.Name=\"X\""));
    }

    [Fact]
    public void WindowsFolderIsNotTrustedByPath()
    {
        Assert.True(Signatures.IsComponentFolder(Path.Combine(Environment.SystemDirectory, "notepad.exe")));
        Assert.False(Signatures.IsComponentFolder(Path.Combine(KnownPaths.Windows, "Temp", "x.exe")));
        Assert.False(Signatures.IsComponentFolder(Path.Combine(KnownPaths.Windows, "Tasks", "x.exe")));
        Assert.False(Signatures.IsComponentFolder(Path.Combine(Environment.SystemDirectory, "Tasks", "x.exe")));
        // A real Windows component is recognised through the catalog, an unsigned file in Windows\Temp is not.
        var notepad = Signatures.Check(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
        Assert.Equal(SignatureStatus.Signed, notepad.Status);
        Assert.True(notepad.IsMicrosoft);
        string stray = Path.Combine(KnownPaths.Windows, "Temp", "wctest-" + Guid.NewGuid().ToString("N") + ".exe");
        try
        {
            File.WriteAllBytes(stray, [0x4D, 0x5A, 0, 0, 0, 0]);
            var verdict = Signatures.Check(stray);
            Assert.Equal(SignatureStatus.Unsigned, verdict.Status);
            Assert.False(verdict.IsMicrosoft);
        }
        catch (UnauthorizedAccessException) { }
        finally { try { File.Delete(stray); } catch (IOException) { } }
        // The name alone does not make a publisher Microsoft once the real check has spoken.
        Assert.False(new SignatureInfo(SignatureStatus.Signed, "Microsoft Lookalike Ltd", false).IsMicrosoft);
        Assert.True(new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows").IsMicrosoft);
    }

    [Fact]
    public async Task HelperRefusesFoldersOfInstalledPrograms()
    {
        var installed = new List<Tramontana.Modules.Apps.InstalledProgram>
        {
            new() { Id = "x", Name = "Foo", InstallLocation = Path.Combine(KnownPaths.ProgramFiles, "Foo") },
        };
        Assert.NotNull(HelperService.ProgramFolderObjection(Path.Combine(KnownPaths.ProgramFiles, "Foo"), installed, checkRunning: false));
        Assert.NotNull(HelperService.ProgramFolderObjection(KnownPaths.ProgramFiles + @"\Foo", installed, checkRunning: false));
        Assert.Null(HelperService.ProgramFolderObjection(Path.Combine(KnownPaths.ProgramFiles, "Foo", "cache"), installed, checkRunning: false));
        Assert.Null(HelperService.ProgramFolderObjection(Path.Combine(KnownPaths.ProgramFiles, "Gone"), installed, checkRunning: false));
        Assert.Null(HelperService.ProgramFolderObjection(Path.Combine(KnownPaths.Windows, "Temp", "x"), installed, checkRunning: true));
        // Duplicates in a request no longer break the whole answer.
        var dry = await HelperService.HandleAsync(new HelperRequest { Operation = HelperOperation.Remove, Mode = RemovalMode.DryRun, Paths = [@"C:\Users", @"C:\Users", "not a path"] }, CancellationToken.None);
        Assert.True(dry.Ok, dry.Error);
        Assert.Equal(3, dry.Outcomes.Length);
        Assert.Equal(RemovalError.InvalidPath, dry.Outcomes[2].Error);
    }

    [Fact]
    public void IgnoringNeverHidesADanger()
    {
        var danger = new Finding("d", Categories.Persistence, "Pericolo", "r", Severity.Danger);
        var warning = new Finding("w", Categories.Persistence, "Avviso", "r", Severity.Warning);
        var report = ProtectionReport.Markdown([danger, warning], ignored: ["d", "w"]);
        Assert.Contains("Pericolo", report);
        Assert.DoesNotContain("### Avviso", report);
    }

    [Fact]
    public void ChangedRuleFilesAreRefusedUntilConfirmed()
    {
        using var temp = new TempDir();
        var store = new Tramontana.Modules.Protection.Rules.RuleStore(temp.Dir("Rules"));
        string yara = temp.File(@"Rules\yara64.exe", 64);
        string rules = temp.File(@"Rules\custom.yar", 32);
        var files = store.Files();
        var yaraFile = files.Single(f => f.Name == "yara64.exe");
        var rulesFile = files.Single(f => f.Name == "custom.yar");
        var pins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["yara64.exe"] = new string('0', 64), ["custom.yar"] = rulesFile.Sha256 };
        Assert.Equal(Tramontana.Modules.Protection.Rules.RulePins.Verdict.Changed, Tramontana.Modules.Protection.Rules.RulePins.Check(pins, yaraFile));
        Assert.Equal(Tramontana.Modules.Protection.Rules.RulePins.Verdict.Confirmed, Tramontana.Modules.Protection.Rules.RulePins.Check(pins, rulesFile));
        Assert.Equal(Tramontana.Modules.Protection.Rules.RulePins.Verdict.Unconfirmed, Tramontana.Modules.Protection.Rules.RulePins.Check(null, rulesFile));
        // The scan reports the swapped yara64.exe as a danger and never runs it (the fake binary would fail loudly).
        var check = new Tramontana.Modules.Protection.Checks.SignatureScanCheck(store, new Tramontana.Modules.Protection.Checks.ScanCache(temp.Sub("cache.json")), onlyExtra: true) { Pins = pins };
        var findings = check.Run(new CheckContext { Startup = [] }).ToList();
        var changed = Assert.Single(findings, f => f.Id == "rules-changed|yara64.exe");
        Assert.Equal(Severity.Danger, changed.Severity);
        // Nothing confirmed at all: a warning, and yara64.exe still not run.
        var unconfirmed = new Tramontana.Modules.Protection.Checks.SignatureScanCheck(store, new Tramontana.Modules.Protection.Checks.ScanCache(temp.Sub("cache2.json")), onlyExtra: true) { Pins = null }
            .Run(new CheckContext { Startup = [] }).ToList();
        Assert.Contains(unconfirmed, f => f.Id == "rules-unconfirmed");
        Assert.True(File.Exists(yara) && File.Exists(rules));
    }

    [Fact]
    public void SignerPinAcceptsOnlyTheRightCertificate()
    {
        using var temp = new TempDir();
        string unsigned = temp.File("Tramontana.exe", 300);
        Assert.False(Signatures.IsSignedBy(unsigned, "0000000000000000000000000000000000000000"));
        // A signed build demands the signature of the caller even when the hash of the dll matches.
        temp.File("Tramontana.dll", 300);
        string hash = PipeSecurityChecks.Sha256(temp.Sub("Tramontana.dll"));
        Assert.Null(HelperIdentity.Objection(unsigned, temp.Path, hash, true, expectedSigner: null));
        Assert.NotNull(HelperIdentity.Objection(unsigned, temp.Path, hash, true, expectedSigner: "0000000000000000000000000000000000000000"));
        // A Microsoft file with an embedded signature: right thumbprint yes, wrong thumbprint no.
        string dotnet = Path.Combine(KnownPaths.ProgramFiles, "dotnet", "dotnet.exe");
        if (!File.Exists(dotnet)) return;
#pragma warning disable SYSLIB0057
        using var signer = new System.Security.Cryptography.X509Certificates.X509Certificate2(System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(dotnet));
#pragma warning restore SYSLIB0057
        Assert.True(Signatures.IsSignedBy(dotnet, signer.Thumbprint));
        Assert.False(Signatures.IsSignedBy(dotnet, "0000000000000000000000000000000000000000"));
    }

    /// <summary>The published pair as installed: trhelper.exe reports hash and signer, and Tramontana.exe passes the very checks the helper runs.</summary>
    [Fact]
    public void InstalledAppPassesTheHelperChecks()
    {
        string folder = Path.Combine(KnownPaths.ProgramFiles, "Tramontana");
        string app = Path.Combine(folder, "Tramontana.exe");
        string helper = Path.Combine(folder, "trhelper.exe");
        if (!File.Exists(app) || !File.Exists(helper)) return;
        var info = new ProcessStartInfo(helper, "--identity") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
        using var p = Process.Start(info)!;
        string identity = p.StandardOutput.ReadToEnd().Trim();
        p.WaitForExit(10_000);
        var parts = identity.Split('|');
        if (parts.Length != 2 || parts[0].Length == 0) return; // a development build without identity
        string hash = parts[0];
        string? signer = parts[1].Length == 0 ? null : parts[1];
        Assert.Null(HelperIdentity.Objection(app, folder, hash, true, signer));
        Assert.NotNull(HelperIdentity.Objection(app, folder, hash, true, "0000000000000000000000000000000000000000"));
        Assert.NotNull(HelperIdentity.Objection(helper, folder, hash, true, signer));
        if (signer is not null) Assert.True(Signatures.IsSignedBy(app, signer));
    }
}
