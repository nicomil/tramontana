using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Privacy;

namespace WinCleaner.Tests;

public class PrivacyStartupTests
{
    private static void Exec(string db, string sql)
    {
        using var c = new SqliteConnection($"Data Source={db};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public void SqlCleaningKeepsABackupInTheRecycleBinAndSkipsMissingTables()
    {
        using var t = new TempDir();
        var db = t.Sub("History");
        Exec(db, "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT); CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER);" +
                 "INSERT INTO urls(url) VALUES('https://a'),('https://b'); INSERT INTO visits(url) VALUES(1),(2);");
        var item = new PrivacyItem("test|History", "TestBrowser", "Default", PrivacyKind.History, 2,
            new PrivacyAction.Sql(db, ["DELETE FROM visits", "DELETE FROM urls", "DELETE FROM segments"]), ["no-such-process"]);

        PrivacyCleaner.Clean(item, RemovalMode.Recycle);

        using (var reader = SqliteDb.OpenReadOnly(db)!)
        {
            Assert.Equal(0, reader.Count("urls"));
            Assert.Equal(0, reader.Count("visits"));
        }
        var backup = RecycleBin.List(db[0]).Where(i => i.OriginalPath.Contains("WinCleaner, copia di TestBrowser Default History")).ToList();
        Assert.NotEmpty(backup);
        var copy = Directory.GetFiles(backup[0].DataPath).Single();
        using (var saved = SqliteDb.OpenReadOnly(copy)!) Assert.Equal(2, saved.Count("urls"));
        foreach (var b in backup) RecycleBin.Purge(b);
    }

    [Fact]
    public void RunningBrowsersAreRefused()
    {
        var self = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
        var item = new PrivacyItem("x", "Test", null, PrivacyKind.Cookies, 1, new PrivacyAction.Clipboard(), [self]);
        Assert.Throws<PrivacyException>(() => PrivacyCleaner.Clean(item, RemovalMode.Recycle));
    }

    [Fact]
    public void StartupApprovedFlagsMatchTaskManager()
    {
        string key = @"Software\WinCleanerTest-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            var item = new StartupItem { Id = "x", Name = "App", Kind = StartupKind.RunKey, Location = "test", ApprovedKey = @"HKEY_CURRENT_USER\" + key, ValueName = "App" };
            Assert.True(StartupManager.IsApproved(item.ApprovedKey, "App"));
            StartupManager.SetApproved(item, enabled: false);
            using (var k = Registry.CurrentUser.OpenSubKey(key)!) Assert.Equal(0x03, ((byte[])k.GetValue("App")!)[0]);
            Assert.False(StartupManager.IsApproved(item.ApprovedKey, "App"));
            StartupManager.SetApproved(item, enabled: true);
            Assert.True(StartupManager.IsApproved(item.ApprovedKey, "App"));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(key, throwOnMissingSubKey: false);
        }
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --tray", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Program Files\\App\\app.exe --tray", "C:\\Program Files\\App\\app.exe")]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL", null)]
    public void StartupCommandsResolveTheirExecutable(string command, string? expected)
    {
        var exe = StartupManager.ExecutableOf(command);
        Assert.Equal(expected ?? Path.Combine(Environment.SystemDirectory, "rundll32.exe"), exe);
    }

    [Fact]
    public void ScriptsAndTempFoldersAtStartupAreFlagged()
    {
        var temp = new StartupItem { Id = "a", Name = "x", Kind = StartupKind.RunKey, Location = "t", Executable = Path.Combine(KnownPaths.Temp, "x.exe"), Command = "x" };
        Assert.Equal(WinCleaner.Modules.Protection.Severity.Danger, WinCleaner.Modules.Protection.ProtectionScanner.Assess(temp)!.Value.Severity);
        var ps = new StartupItem { Id = "b", Name = "y", Kind = StartupKind.RunKey, Location = "t",
            Executable = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), Command = "powershell -w hidden -enc AAAA" };
        Assert.Equal(WinCleaner.Modules.Protection.Severity.Danger, WinCleaner.Modules.Protection.ProtectionScanner.Assess(ps)!.Value.Severity);
    }
}
