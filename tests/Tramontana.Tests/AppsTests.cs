using Microsoft.Win32;
using Tramontana.Core;
using Tramontana.Modules.Apps;

namespace Tramontana.Tests;

public class AppsTests
{
    [Theory]
    [InlineData("Opera Stable 131.0.5877.116", "Opera Stable")]
    [InlineData("Python 3.11.9 (64-bit)", "Python")]
    [InlineData("PowerToys (Preview) x64", "PowerToys (Preview)")]
    [InlineData("Ollama version 0.31.1", "Ollama")]
    [InlineData("VLC media player", "VLC media player")]
    [InlineData("Cursor (User)", "Cursor")]
    public void NormalizesProgramNames(string name, string expected) => Assert.Equal(expected, LeftoverFinder.NormalizeName(name));

    [Fact]
    public void ParsesWingetTablesInAnyLanguage()
    {
        const string output = """
            Nome                        Id                        Versione       Disponibile    Origine
            -------------------------------------------------------------------------------------------
            Cursor (User)               Anysphere.Cursor          3.9.16         3.20.14        winget
            Opera Stable 131.0.5877.116 Opera.Opera               131.0.5877.116 137.0.6036.39  winget
            PowerToys (Preview) x64     XP89DCGQ3K6VLD            0.100.0        0.102.2933.0   msstore
            3 aggiornamenti disponibili.
            """;
        var updates = WingetUpdates.Parse(output);
        Assert.Equal(3, updates.Count);
        Assert.Equal(new AvailableUpdate("Opera Stable 131.0.5877.116", "Opera.Opera", "131.0.5877.116", "137.0.6036.39", "winget"), updates[1]);
        Assert.Equal("msstore", updates[2].Source);
    }

    [Fact]
    public void UninstallCommandsAreParsedSafely()
    {
        var msi = new InstalledProgram { Id = "x", Name = "x", UninstallString = "MsiExec.exe /I{12345678-1234-1234-1234-123456789ABC}" };
        Assert.Equal(("msiexec.exe", "/x {12345678-1234-1234-1234-123456789ABC}"), ProgramUninstaller.Command(msi));
        var steam = new InstalledProgram { Id = "x", Name = "x", UninstallString = "steam://uninstall/570" };
        Assert.Equal(("steam://uninstall/570", ""), ProgramUninstaller.Command(steam));
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var quoted = new InstalledProgram { Id = "x", Name = "x", UninstallString = $"\"{cmd}\" /c echo" };
        Assert.Equal((cmd, "/c echo"), ProgramUninstaller.Command(quoted));
        var missing = new InstalledProgram { Id = "x", Name = "x", UninstallString = @"C:\nope\unins000.exe /SILENT" };
        Assert.Null(ProgramUninstaller.Command(missing));
    }

    [Theory]
    [InlineData(@"HKCU\Software\Vendor\App", null, true)]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Vendor\App", null, true)]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\App", null, true)]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "App", true)]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", null, false)]
    [InlineData(@"HKCU\Software\Microsoft\Office", null, false)]
    [InlineData(@"HKCU\Software\Classes\.txt", null, false)]
    [InlineData(@"HKCU\Software\Policies\Vendor", null, false)]
    [InlineData(@"HKCU\Software", null, false)]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\x", null, false)]
    [InlineData(@"HKEY_USERS\S-1-5-18\Software\Vendor", null, false)]
    [InlineData(@"HKCU\Software\\Vendor", null, false)]
    public void RegistryAllowList(string key, string? value, bool allowed) =>
        Assert.Equal(allowed, RegistryCleaner.IsAllowed(new RegistryTarget(key, value)));

    [Fact]
    public void RegistryKeysAreBackedUpBeforeDeletion()
    {
        string name = "TramontanaTest-" + Guid.NewGuid().ToString("N")[..8];
        using (var key = Registry.CurrentUser.CreateSubKey($@"Software\{name}\App"))
            key.SetValue("Setting", "42");
        using var t = new TempDir();
        var cleaner = new RegistryCleaner(RemovalMode.Delete, null, t.Path);

        var outcome = cleaner.Remove([new RegistryTarget($@"HKCU\Software\{name}")]).Single();

        Assert.True(outcome.Succeeded, outcome.Message);
        Assert.Null(Registry.CurrentUser.OpenSubKey($@"Software\{name}"));
        var backup = File.ReadAllText(outcome.Message!);
        Assert.Contains(name, backup);
        Assert.Contains("\"Setting\"=\"42\"", backup);
    }

    [Fact]
    public void VersionsCompareNumerically()
    {
        Assert.True(InstallersModule.CompareVersions("10.2", "9.15") > 0);
        Assert.Equal(0, InstallersModule.CompareVersions("3.0.24", "3.0.24.0"));
        Assert.True(InstallersModule.CompareVersions("3.0.23", "3.0.24") < 0);
    }

    [Fact]
    public void InstallersMatchInstalledPrograms()
    {
        var installed = new List<InstalledProgram> { new() { Id = "a", Name = "VLC media player", Version = "3.0.24" } };
        Assert.NotNull(InstallersModule.FindInstalled("VLC media player", installed));
        Assert.Null(InstallersModule.FindInstalled("Setup", installed));
        Assert.Null(InstallersModule.FindInstalled("VLC Remote", installed));
    }
}

public class HelperPolicyTests
{
    [Theory]
    [InlineData(@"C:\Program Files\WindowsApps\Some.App_1.0", true)]
    [InlineData(@"C:\Program Files\Common Files\Vendor", true)]
    [InlineData(@"C:\ProgramData\Microsoft\Crypto", true)]
    [InlineData(@"C:\ProgramData\Microsoft\Windows\WER\ReportArchive\x", false)]
    [InlineData(@"C:\Program Files\OldApp", false)]
    public void SharedFoldersAreBlocked(string path, bool blocked) =>
        Assert.Equal(blocked, Tramontana.Modules.Helper.HelperService.IsBlocked(path));

    [Fact]
    public async Task HelperRefusesSystemFoldersEvenWhenAsked()
    {
        var response = await Tramontana.Modules.Helper.HelperService.HandleAsync(new Tramontana.Modules.Helper.HelperRequest
        {
            Operation = Tramontana.Modules.Helper.HelperOperation.Remove,
            Mode = RemovalMode.DryRun,
            Paths = [Path.Combine(Environment.SystemDirectory, "drivers"), Path.Combine(KnownPaths.ProgramFiles, "WindowsApps"), KnownPaths.Windows, KnownPaths.UserProfile],
        }, CancellationToken.None);
        Assert.True(response.Ok);
        Assert.All(response.Outcomes, o => Assert.False(o.Succeeded));
    }

    [Fact]
    public async Task HelperRefusesUnknownTasksServicesAndRegistry()
    {
        var task = await Tramontana.Modules.Helper.HelperService.HandleAsync(new() { Operation = Tramontana.Modules.Helper.HelperOperation.DeleteTask, Name = @"\Microsoft\Windows\Defrag\ScheduledDefrag" }, CancellationToken.None);
        Assert.False(task.Ok);
        var service = await Tramontana.Modules.Helper.HelperService.HandleAsync(new() { Operation = Tramontana.Modules.Helper.HelperOperation.SetServiceStart, Name = "WinDefend", Number = 4 }, CancellationToken.None);
        Assert.False(service.Ok);
        var registry = await Tramontana.Modules.Helper.HelperService.HandleAsync(new() { Operation = Tramontana.Modules.Helper.HelperOperation.RemoveRegistry, Mode = RemovalMode.DryRun,
            Registry = [new RegistryTarget(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend")] }, CancellationToken.None);
        Assert.Equal(RemovalError.OutsideAllowedRoots, registry.Outcomes.Single().Error);
        var approved = await Tramontana.Modules.Helper.HelperService.HandleAsync(new() { Operation = Tramontana.Modules.Helper.HelperOperation.SetStartupApproved,
            Key = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Name = "SecurityHealth" }, CancellationToken.None);
        Assert.False(approved.Ok);
    }

    [Fact]
    public void SpinnerAndProgressRedrawsDoNotShiftTheColumns()
    {
        string output =
            "\r   - \r   \\ \r   | \r   / \r                                                                \r" +
            "Nome                        Id                        Versione       Disponibile    Origine\r\n" +
            "-------------------------------------------------------------------------------------------\r\n" +
            "\u001b[0mGit                         Git.Git                   2.54.0         2.56.0.3       winget\r\n" +
            "VLC media player            VideoLAN.VLC              3.0.23         3.0.24         winget\r\n" +
            "2 aggiornamenti disponibili.\r\n";
        var updates = WingetUpdates.Parse(output);
        Assert.Equal(2, updates.Count);
        Assert.Equal(new AvailableUpdate("Git", "Git.Git", "2.54.0", "2.56.0.3", "winget"), updates[0]);
        Assert.Equal("VideoLAN.VLC", updates[1].Id);
    }

    [Theory]
    [InlineData("PowerToys (Preview) x64", "PowerToys (Preview) x64", true)]
    [InlineData("Ollama version 0.31.1", "ollama version 0.31.1", true)]
    [InlineData("Microsoft Visual Studio Code (User", "Microsoft Visual Studio Code (User)", true)]
    [InlineData("Git", "Git Extensions", false)]
    [InlineData("", "Git", false)]
    [InlineData("Python 3.12", "Python 3.12.4 (64-bit)", false)]
    public void MatchesWingetNamesToInstalledPrograms(string winget, string program, bool expected) =>
        Assert.Equal(expected, WingetUpdates.MatchesProgram(winget, program));

    [Fact]
    public void ExplainsWingetFailuresInsteadOfQuotingLogPaths()
    {
        Assert.Contains("chiudilo", WingetUpdates.Describe(WingetUpdates.InstallerFailed, @"Il log del programma di installazione è disponibile in: 'C:\x.log'"));
        Assert.Contains("Microsoft Store", WingetUpdates.Describe(WingetUpdates.UpdateNotApplicable, "Una versione più recente del pacchetto è disponibile in un'origine configurata, ma non si applica"));
        Assert.Equal("qualcosa", WingetUpdates.Describe(1, "qualcosa"));
        Assert.Contains("0x8A150001", WingetUpdates.Describe(unchecked((int)0x8A150001), null));
    }

    [Fact]
    public void RunningProcessesLooksOnlyInTheProgramsOwnFolder()
    {
        var update = new AvailableUpdate("Fake Program", "Fake.Program", "1", "2", "winget");
        var programs = new[]
        {
            new InstalledProgram { Id = "a", Name = "Fake Program", InstallLocation = Path.Combine(KnownPaths.ProgramFiles, "FakeProgram-" + Guid.NewGuid().ToString("N")) },
            new InstalledProgram { Id = "b", Name = "Other", InstallLocation = Environment.SystemDirectory },
        };
        Assert.Empty(WingetUpdates.RunningProcesses(update, programs));
        // A program that claims a shared folder as its own must not make every process "its" process.
        var shared = new[] { new InstalledProgram { Id = "c", Name = "Fake Program", InstallLocation = KnownPaths.ProgramFiles } };
        Assert.Empty(WingetUpdates.RunningProcesses(update, shared));
    }
}
