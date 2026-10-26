using WinCleaner.Core;

namespace WinCleaner.Tests;

public class PathGuardTests
{
    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Temp\x")]
    [InlineData(@"D:\data\file.txt")]
    [InlineData(@"C:\")]
    public void AcceptsPlainPaths(string path) => Assert.True(PathGuard.IsValidPath(path));

    [Theory]
    [InlineData(@"C:\a\..\b")]
    [InlineData(@"C:\a\.\b")]
    [InlineData(@"\\?\C:\a")]
    [InlineData(@"\\.\C:\a")]
    [InlineData(@"\\server\share\a")]
    [InlineData(@"C:\a\file.txt:stream")]
    [InlineData(@"C:\a\name.")]
    [InlineData(@"C:\a\name ")]
    [InlineData(@"C:/a/b")]
    [InlineData(@"C:\a\\b")]
    [InlineData(@"C:\a\")]
    [InlineData(@"C:\a\*")]
    [InlineData(@"C:\a\b?")]
    [InlineData(@"a\b")]
    [InlineData(@"C:a\b")]
    [InlineData("")]
    public void RefusesTrickyPaths(string path) => Assert.False(PathGuard.IsValidPath(path));

    [Fact]
    public void StrictlyInsideIgnoresCaseButNotPrefixesOfNames()
    {
        Assert.True(PathGuard.IsStrictlyInside(@"C:\Root\x", @"c:\root"));
        Assert.False(PathGuard.IsStrictlyInside(@"C:\Rooted\x", @"C:\Root"));
        Assert.False(PathGuard.IsStrictlyInside(@"C:\Root", @"C:\Root"));
    }
}

public class SafeRemoverTests
{
    private static SafeRemover Remover(string root, RemovalMode mode = RemovalMode.Delete) =>
        new([root], mode, log: null, protectedPaths: []);

    [Fact]
    public void DeletesFilesAndFoldersInsideTheRoot()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var file = t.File(@"root\a.bin", 1000);
        t.File(@"root\folder\b.bin", 500);
        t.File(@"root\folder\deep\c.bin", 250);

        var outcomes = Remover(root).Remove([file, t.Sub("root", "folder")]);

        Assert.All(outcomes, o => Assert.True(o.Succeeded, o.Error.ToString()));
        Assert.Equal(1000, outcomes[0].Freed);
        Assert.Equal(750, outcomes[1].Freed);
        Assert.False(File.Exists(file));
        Assert.False(Directory.Exists(t.Sub("root", "folder")));
        Assert.True(Directory.Exists(root));
    }

    [Fact]
    public void RefusesTheRootItselfAndPathsOutside()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var outside = t.File(@"other\keep.txt");
        var remover = Remover(root);

        Assert.Equal(RemovalError.IsAllowedRoot, remover.Validate(root));
        Assert.Equal(RemovalError.OutsideAllowedRoots, remover.Validate(outside));
        Assert.Equal(RemovalError.OutsideAllowedRoots, remover.Validate(t.Sub("rootx", "a")));
        Assert.Equal(RemovalError.InvalidPath, remover.Validate(root + @"\..\other\keep.txt"));
        Assert.True(File.Exists(outside));
    }

    [Fact]
    public void JunctionItemIsRemovedAsALinkOnly()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var victim = t.File(@"victim\important.docx", 300);
        var link = t.Sub("root", "link");
        TempDir.Junction(link, t.Sub("victim"));

        var outcome = Remover(root).Remove([link]).Single();

        Assert.True(outcome.Succeeded, outcome.Error.ToString());
        Assert.False(Directory.Exists(link));
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public void JunctionInsideAFolderIsNotEntered()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var victim = t.File(@"victim\important.docx", 300);
        t.File(@"root\cache\data.bin", 100);
        TempDir.Junction(t.Sub("root", "cache", "sneaky"), t.Sub("victim"));

        var outcome = Remover(root).Remove([t.Sub("root", "cache")]).Single();

        Assert.True(outcome.Succeeded, outcome.Error.ToString());
        Assert.Equal(100, outcome.Freed);
        Assert.False(Directory.Exists(t.Sub("root", "cache")));
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public void JunctionInThePathIsRefused()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var victim = t.File(@"victim\important.docx", 300);
        TempDir.Junction(t.Sub("root", "link"), t.Sub("victim"));

        var outcome = Remover(root).Remove([t.Sub("root", "link", "important.docx")]).Single();

        Assert.Equal(RemovalError.ReparsePointInPath, outcome.Error);
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public void DryRunMeasuresWithoutRemoving()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        t.File(@"root\folder\a.bin", 400);
        t.File(@"root\folder\b.bin", 600);

        var outcome = Remover(root, RemovalMode.DryRun).Remove([t.Sub("root", "folder")]).Single();

        Assert.True(outcome.Succeeded);
        Assert.Equal(1000, outcome.Freed);
        Assert.True(Directory.Exists(t.Sub("root", "folder")));
    }

    [Fact]
    public void ReadOnlyFilesAreDeleted()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var file = t.File(@"root\ro.txt");
        File.SetAttributes(file, FileAttributes.ReadOnly);

        var outcome = Remover(root).Remove([file]).Single();

        Assert.True(outcome.Succeeded, outcome.Message);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public void FilesInUseAreReportedAndTheRestIsRemoved()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var locked = t.File(@"root\folder\locked.bin", 100);
        var free = t.File(@"root\folder\free.bin", 200);

        using (new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var outcome = Remover(root).Remove([t.Sub("root", "folder")]).Single();
            Assert.True(outcome.Succeeded);
            Assert.Equal(200, outcome.Freed);
            Assert.Equal(1, outcome.InUse);
        }
        Assert.True(File.Exists(locked));
        Assert.False(File.Exists(free));
    }

    [Fact]
    public void LockedSingleFileIsInUse()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var locked = t.File(@"root\locked.bin");
        using var stream = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None);

        var outcome = Remover(root).Remove([locked]).Single();

        Assert.Equal(RemovalError.InUse, outcome.Error);
    }

    [Fact]
    public void ProtectedPathsAndTheirParentsAreRefused()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var keep = t.File(@"root\app\WinCleaner\operations.log");
        var remover = new SafeRemover([root], RemovalMode.Delete, null, [t.Sub("root", "app", "WinCleaner")]);

        Assert.Equal(RemovalError.SystemProtected, remover.Validate(t.Sub("root", "app")));
        Assert.Equal(RemovalError.SystemProtected, remover.Validate(keep));
    }

    [Fact]
    public void RecycleMovesToTheBinWithARestorableRecord()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var file = t.File(@"root\recycle-me.txt", 1234);

        var outcome = Remover(root, RemovalMode.Recycle).Remove([file]).Single();

        Assert.True(outcome.Succeeded, $"{outcome.Error} {outcome.Message}");
        Assert.False(File.Exists(file));
        var item = RecycleBin.List(file[0]).Single(i => string.Equals(i.OriginalPath, file, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1234, item.Size);
        Assert.True(File.Exists(item.DataPath));
        RecycleBin.Purge(item);
        Assert.False(File.Exists(item.DataPath));
    }

    [Fact]
    public void RecycleMovesFoldersWithoutEnteringLinks()
    {
        using var t = new TempDir();
        var root = t.Dir("root");
        var victim = t.File(@"victim\important.docx", 300);
        t.File(@"root\folder\a.bin", 10);
        TempDir.Junction(t.Sub("root", "folder", "link"), t.Sub("victim"));

        var outcome = Remover(root, RemovalMode.Recycle).Remove([t.Sub("root", "folder")]).Single();

        Assert.True(outcome.Succeeded, $"{outcome.Error} {outcome.Message}");
        Assert.Equal(10, outcome.Freed);
        var item = RecycleBin.List(root[0]).Single(i => i.OriginalPath.Equals(t.Sub("root", "folder"), StringComparison.OrdinalIgnoreCase));
        RecycleBin.Purge(item);
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public void InfoRecordRoundTrips()
    {
        var when = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var record = RecycleBin.InfoRecord(@"C:\x\y.txt", 42, when);
        var parsed = RecycleBin.ParseInfo(record);
        Assert.Equal((@"C:\x\y.txt", 42L, when), parsed);
    }
}
