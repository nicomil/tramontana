using System.Diagnostics;
using Tramontana.Core;
using Tramontana.Modules;

namespace Tramontana.Tests;

public class FilesModulesTests
{
    private static void HardLink(string link, string target)
    {
        var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /H \"{link}\" \"{target}\"") { UseShellExecute = false, RedirectStandardOutput = true })!;
        p.WaitForExit();
        Assert.True(File.Exists(link));
    }

    private static byte[] Random(int size, int seed)
    {
        var data = new byte[size];
        new Random(seed).NextBytes(data);
        return data;
    }

    [Fact]
    public void SpaceLensCountsHardLinksOnceAndSkipsJunctions()
    {
        using var t = new TempDir();
        var a = t.File(@"scan\a.bin");
        File.WriteAllBytes(a, Random(1_000_000, 1));
        t.Dir(@"scan\sub");
        HardLink(t.Sub("scan", "sub", "a-link.bin"), a);
        t.File(@"outside\big.bin");
        File.WriteAllBytes(t.Sub("outside", "big.bin"), Random(3_000_000, 2));
        TempDir.Junction(t.Sub("scan", "junction"), t.Sub("outside"));

        var tree = new SpaceLensScanner { MinimumFileSize = 0 }.Scan(t.Sub("scan"));

        Assert.InRange(tree.Size, 1_000_000, 1_100_000);
        Assert.DoesNotContain(tree.Children, c => c.Name == "junction");
    }

    [Fact]
    public async Task DuplicatesKeepTheCopyOutsideDownloadsAndPreselectOnlyDownloads()
    {
        using var t = new TempDir();
        var content = Random(2_000_000, 3);
        var docs = t.File(@"Documents\report.pdf"); File.WriteAllBytes(docs, content);
        var dl = t.File(@"Downloads\report.pdf"); File.WriteAllBytes(dl, content);
        var other = t.File(@"Pictures\report (1).pdf"); File.WriteAllBytes(other, content);
        var different = t.File(@"Documents\other.pdf"); File.WriteAllBytes(different, Random(2_000_000, 4));
        HardLink(t.Sub("Documents", "report-link.pdf"), docs);

        var module = new DuplicatesModule([t.Sub("Documents"), t.Sub("Downloads"), t.Sub("Pictures")], t.Sub("Downloads"));
        var report = await module.ScanAsync(null, CancellationToken.None);

        var group = Assert.Single(report.Categories);
        Assert.Equal(3, group.Items.Count);
        Assert.False(PathGuard.IsStrictlyInside(group.Keep!, t.Sub("Downloads")));
        Assert.Equal([dl], group.Items.Where(i => i.AutoSelect).Select(i => i.Path));
        Assert.True(DuplicatesModule.StillDuplicates([dl], group.Keep!));
        File.WriteAllBytes(group.Keep!, Random(2_000_000, 5));
        Assert.False(DuplicatesModule.StillDuplicates([dl], group.Keep!));
    }

    [Fact]
    public void SelectionNeverRemovesTheKeptCopyOrAllCopies()
    {
        var items = new List<ScanItem> { new(@"C:\a", 1, RiskLevel.Medium, false, false), new(@"C:\b", 1, RiskLevel.Medium, true, false) };
        var report = new ScanReport("dup", [new ScanCategory("g", "g", items) { Keep = @"C:\a" }]);

        Assert.Empty(Selection.UnsafeCopyGroups(report, new HashSet<string> { @"C:\b" }));
        Assert.Single(Selection.UnsafeCopyGroups(report, new HashSet<string> { @"C:\a" }));
        Assert.Single(Selection.UnsafeCopyGroups(report, new HashSet<string> { @"C:\a", @"C:\b" }));
    }

    [Fact]
    public void SimilarHashesAreClustered()
    {
        ulong a = 0xF0F0_F0F0_F0F0_F0F0;
        var groups = SimilarImagesModule.Cluster([a, a ^ 0b111, 0x0F0F_0F0F_0F0F_0F0F, a ^ 0xFF00_FF00_0000], 5);
        Assert.Equal([0, 1], Assert.Single(groups).Order());
    }

    [Fact]
    public void FileKindsByExtension()
    {
        Assert.Equal(FileKind.Video, FileKinds.Of(@"C:\x\film.MKV"));
        Assert.Equal(FileKind.DiskImage, FileKinds.Of(@"C:\x\setup.msi"));
        Assert.Equal(FileKind.Other, FileKinds.Of(@"C:\x\file.unknownext"));
    }
}
