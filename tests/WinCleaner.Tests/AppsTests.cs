using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Apps;

namespace WinCleaner.Tests;

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
        string name = "WinCleanerTest-" + Guid.NewGuid().ToString("N")[..8];
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
        Assert.Equal(blocked, WinCleaner.Modules.Helper.HelperService.IsBlocked(path));

    [Fact]
    public async Task HelperRefusesSystemFoldersEvenWhenAsked()
    {
        var response = await WinCleaner.Modules.Helper.HelperService.HandleAsync(new WinCleaner.Modules.Helper.HelperRequest
        {
            Operation = WinCleaner.Modules.Helper.HelperOperation.Remove,
            Mode = RemovalMode.DryRun,
            Paths = [Path.Combine(Environment.SystemDirectory, "drivers"), Path.Combine(KnownPaths.ProgramFiles, "WindowsApps"), KnownPaths.Windows, KnownPaths.UserProfile],
        }, CancellationToken.None);
        Assert.True(response.Ok);
        Assert.All(response.Outcomes, o => Assert.False(o.Succeeded));
    }

    [Fact]
    public async Task HelperRefusesUnknownTasksServicesAndRegistry()
    {
        var task = await WinCleaner.Modules.Helper.HelperService.HandleAsync(new() { Operation = WinCleaner.Modules.Helper.HelperOperation.DeleteTask, Name = @"\Microsoft\Windows\Defrag\ScheduledDefrag" }, CancellationToken.None);
        Assert.False(task.Ok);
        var service = await WinCleaner.Modules.Helper.HelperService.HandleAsync(new() { Operation = WinCleaner.Modules.Helper.HelperOperation.SetServiceStart, Name = "WinDefend", Number = 4 }, CancellationToken.None);
        Assert.False(service.Ok);
        var registry = await WinCleaner.Modules.Helper.HelperService.HandleAsync(new() { Operation = WinCleaner.Modules.Helper.HelperOperation.RemoveRegistry, Mode = RemovalMode.DryRun,
            Registry = [new RegistryTarget(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend")] }, CancellationToken.None);
        Assert.Equal(RemovalError.OutsideAllowedRoots, registry.Outcomes.Single().Error);
        var approved = await WinCleaner.Modules.Helper.HelperService.HandleAsync(new() { Operation = WinCleaner.Modules.Helper.HelperOperation.SetStartupApproved,
            Key = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Name = "SecurityHealth" }, CancellationToken.None);
        Assert.False(approved.Ok);
    }

    [Fact]
    public void BootstrapQuotesPathsForPowerShell()
    {
        var script = WinCleaner.Modules.Helper.HelperClient.BootstrapScript(@"C:\Users\O'Brien\app\wchelper.exe", "ABC", "--pipe x --parent 1");
        Assert.Contains(@"'C:\Users\O''Brien\app\wchelper.exe'", script);
        Assert.Contains("Get-FileHash", script);
    }
}

public class SharedFolderTests
{
    [Theory]
    [InlineData(@"C:\", true)]
    [InlineData(@"D:\Games", true)]
    [InlineData(@"C:\Program Files", true)]
    [InlineData(@"C:\Program Files\VideoLAN\VLC", false)]
    [InlineData(@"C:\Windows\System32", true)]
    public void SharedFoldersAreNeverAProgramFolder(string folder, bool shared) =>
        Assert.Equal(shared, WinCleaner.Modules.Apps.InstalledPrograms.IsSharedFolder(folder));
}

public class WingetConsoleOutputTests
{
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
}
