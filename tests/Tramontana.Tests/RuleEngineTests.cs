using Tramontana.Core;

namespace Tramontana.Tests;

public class RuleEngineTests
{
    private static RuleEngine Engine(TempDir t, IEnumerable<string>? running = null, DateTime? now = null) =>
        new(token => token == "%ROOT%" ? t.Path : null, running ?? [], now);

    private static CleaningRule Rule(string path, Action<CleaningRuleBuilder>? edit = null)
    {
        var b = new CleaningRuleBuilder { Paths = [path] };
        edit?.Invoke(b);
        return b.Build();
    }

    public sealed class CleaningRuleBuilder
    {
        public string Id = "r";
        public string Category = "c";
        public string[] Paths = [];
        public RuleTarget Target = RuleTarget.Children;
        public string[] Include = [];
        public string[] Excludes = [];
        public double? MinAgeHours;
        public string[] Processes = [];
        public string[] Siblings = [];

        public CleaningRule Build() => new()
        {
            Id = Id, Category = Category, Title = Category, Paths = Paths, Target = Target, Include = Include,
            Excludes = Excludes, MinAgeHours = MinAgeHours, Processes = Processes, RequireAnySibling = Siblings,
        };
    }

    [Fact]
    public void ChildrenOfWildcardFoldersBecomeItems()
    {
        using var t = new TempDir();
        t.File(@"User Data\Default\Cache\a", 10);
        t.File(@"User Data\Profile 1\Cache\b", 20);
        t.File(@"User Data\Profile 1\Other\c", 40);

        var output = Engine(t).Evaluate(new RuleSet { Rules = [Rule(@"%ROOT%\User Data\*\Cache")] });

        var items = output.Categories.Single().Items;
        Assert.Equal(2, items.Count);
        Assert.Equal(30, items.Sum(i => i.Size));
    }

    [Fact]
    public void IncludeAndExcludeFilterNames()
    {
        using var t = new TempDir();
        t.File(@"Explorer\thumbcache_32.db", 10);
        t.File(@"Explorer\thumbcache_idx.db", 10);
        t.File(@"Explorer\ExplorerStartupLog.etl", 10);

        var rule = Rule(@"%ROOT%\Explorer", b => { b.Include = ["thumbcache_*.db"]; b.Excludes = ["*_idx.db"]; });
        var items = Engine(t).Evaluate(new RuleSet { Rules = [rule] }).Categories.Single().Items;

        Assert.Equal("thumbcache_32.db", items.Single().DisplayName);
    }

    [Fact]
    public void RecentItemsAreKeptByMinAge()
    {
        using var t = new TempDir();
        var old = t.File(@"Temp\old.tmp");
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-3));
        t.File(@"Temp\new.tmp");
        var folder = t.File(@"Temp\folder\inner-new.tmp");
        Directory.SetLastWriteTimeUtc(Path.GetDirectoryName(folder)!, DateTime.UtcNow.AddDays(-3));

        var rule = Rule(@"%ROOT%\Temp", b => b.MinAgeHours = 24);
        var items = Engine(t).Evaluate(new RuleSet { Rules = [rule] }).Categories.Single().Items;

        // The folder has a recent file inside, so it is kept too.
        Assert.Equal("old.tmp", items.Single().DisplayName);
    }

    [Fact]
    public void RulesOfRunningProgramsAreSkippedWithANote()
    {
        using var t = new TempDir();
        t.File(@"Chrome\Cache\a");
        var rule = Rule(@"%ROOT%\Chrome\Cache", b => b.Processes = ["chrome"]);

        var output = Engine(t, running: ["Chrome"]).Evaluate(new RuleSet { Rules = [rule] });

        Assert.Empty(output.Categories);
        Assert.Contains(output.Notes, n => n.Contains("chrome.exe"));
    }

    [Fact]
    public void SiblingRequirementDetectsChromiumAppFolders()
    {
        using var t = new TempDir();
        t.File(@"AppA\Cache\x");
        t.File(@"AppA\Local State");
        t.File(@"AppB\Cache\y");

        var rule = Rule(@"%ROOT%\*\Cache", b => { b.Target = RuleTarget.Itself; b.Siblings = ["Local State"]; });
        var items = Engine(t).Evaluate(new RuleSet { Rules = [rule] }).Categories.Single().Items;

        Assert.Equal(t.Sub("AppA", "Cache"), items.Single().Path);
    }

    [Fact]
    public void OverlappingRulesKeepTheOutermostItemOnce()
    {
        using var t = new TempDir();
        t.File(@"Cache\sub\a", 10);

        var outer = Rule(@"%ROOT%\Cache", b => { b.Target = RuleTarget.Itself; b.Category = "outer"; });
        var inner = Rule(@"%ROOT%\Cache\sub", b => { b.Target = RuleTarget.Itself; b.Category = "inner"; });
        var output = Engine(t).Evaluate(new RuleSet { Rules = [inner, outer] });

        Assert.Equal("outer", output.Categories.Single().Id);
    }

    [Fact]
    public void JunctionsAreNotFollowedByWildcards()
    {
        using var t = new TempDir();
        t.File(@"elsewhere\Cache\secret", 10);
        t.Dir("data");
        TempDir.Junction(t.Sub("data", "link"), t.Sub("elsewhere"));

        var output = Engine(t).Evaluate(new RuleSet { Rules = [Rule(@"%ROOT%\data\*\Cache")] });

        Assert.Empty(output.Categories);
    }

    [Fact]
    public void UnknownTokensNeverMatch()
    {
        using var t = new TempDir();
        Assert.Empty(Engine(t).Expand(@"%NOPE%\x"));
    }
}
