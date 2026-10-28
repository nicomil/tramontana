using Tramontana.Core;

namespace Tramontana.Tests;

/// <summary>The move from the WinCleaner folders (up to 0.2) to the Tramontana ones, and what a signature result means.</summary>
public class LegacyDataTests
{
    [Fact]
    public void MovesTheOldUserFolderOnceAndRewritesTheQuarantineIndex()
    {
        using var t = new TempDir();
        string old = t.Sub("WinCleaner"), current = t.Sub("Tramontana");
        Directory.CreateDirectory(old);
        File.WriteAllText(Path.Combine(old, "settings.json"), "{\"DefaultMode\":\"DryRun\"}");
        Directory.CreateDirectory(Path.Combine(old, "Quarantine", "abc"));
        string escapedOld = old.Replace("\\", "\\\\");
        File.WriteAllText(Path.Combine(old, "Quarantine", "index.json"), "[{\"StoredFolder\":\"" + escapedOld + "\\\\Quarantine\\\\abc\",\"StoredName\":\"x.exe\"}]");

        var note = LegacyData.MigrateUser(old, current);

        Assert.Contains("spostati", note);
        Assert.False(Directory.Exists(old));
        Assert.Equal("{\"DefaultMode\":\"DryRun\"}", File.ReadAllText(Path.Combine(current, "settings.json")));
        string index = File.ReadAllText(Path.Combine(current, "Quarantine", "index.json"));
        Assert.Contains(current.Replace("\\", "\\\\") + "\\\\Quarantine\\\\abc", index);
        Assert.DoesNotContain("WinCleaner", index);
        Assert.Null(LegacyData.MigrateUser(old, current));
    }

    [Fact]
    public void WhenBothFoldersExistOnlyMissingSettingsAreCopied()
    {
        using var t = new TempDir();
        string old = t.Sub("WinCleaner"), current = t.Sub("Tramontana");
        Directory.CreateDirectory(old);
        Directory.CreateDirectory(current);
        File.WriteAllText(Path.Combine(old, "settings.json"), "old");
        File.WriteAllText(Path.Combine(old, "other.txt"), "stays");

        Assert.Contains("copiate", LegacyData.MigrateUser(old, current));
        Assert.Equal("old", File.ReadAllText(Path.Combine(current, "settings.json")));
        Assert.True(File.Exists(Path.Combine(old, "other.txt")));

        File.WriteAllText(Path.Combine(current, "settings.json"), "new");
        Assert.Null(LegacyData.MigrateUser(old, current));
        Assert.Equal("new", File.ReadAllText(Path.Combine(current, "settings.json")));
    }

    [Fact]
    public void SystemFolderIsAdoptedOnlyWhenStillAdministratorOnly()
    {
        using var t = new TempDir();
        // A junction where the old folder should be is not the helper's folder: nothing moves.
        string target = t.Sub("elsewhere"), old = t.Sub("WinCleaner"), current = t.Sub("Tramontana");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "settings.json"), "x");
        TempDir.Junction(old, target);
        var note = LegacyData.MigrateSystem(old, current);
        Assert.Contains("non spostata", note);
        Assert.True(Directory.Exists(old));
        Assert.True(File.Exists(Path.Combine(target, "settings.json")));
        Assert.False(Directory.Exists(current));
    }

    [Theory]
    [InlineData(0, SignatureStatus.Signed)]
    [InlineData(unchecked((int)0x800B0109), SignatureStatus.Untrusted)] // CERT_E_UNTRUSTEDROOT: self-signed publisher
    [InlineData(unchecked((int)0x800B0101), SignatureStatus.Untrusted)] // CERT_E_EXPIRED
    [InlineData(unchecked((int)0x80096010), SignatureStatus.Invalid)]   // TRUST_E_BAD_DIGEST: the file was modified
    [InlineData(unchecked((int)0x80096001), SignatureStatus.Invalid)]   // TRUST_E_PROVIDER_UNKNOWN is handled before; any other failure is invalid
    public void AnUntrustedChainIsNotAModifiedFile(int trust, SignatureStatus expected) => Assert.Equal(expected, Signatures.Classify(trust));
}
