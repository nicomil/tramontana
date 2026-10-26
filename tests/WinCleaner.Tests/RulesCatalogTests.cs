using WinCleaner.Core;
using WinCleaner.Modules;

namespace WinCleaner.Tests;

public class RulesCatalogTests
{
    private static string Concrete(string pattern)
    {
        int split = pattern.IndexOf('\\', pattern.IndexOf('%', 1) + 1);
        string head = split < 0 ? pattern : pattern[..split];
        string expanded = KnownPaths.Expand(head) ?? throw new Exception("unknown token in " + pattern);
        if (expanded.Length == 2) expanded += "\\";
        string rest = split < 0 ? "" : pattern[(split + 1)..].Replace('*', 'x').Replace('?', 'x');
        return rest.Length == 0 ? expanded : Path.Combine(expanded, rest);
    }

    [Fact]
    public void EveryRulePathIsInsideItsAllowedRoots()
    {
        var problems = new List<string>();
        foreach (var rule in SystemJunkModule.LoadRules().Rules)
        {
            var roots = rule.Admin ? Roots.System() : Roots.User();
            var items = rule.Admin ? Roots.SystemItems() : [];
            foreach (var pattern in rule.Paths)
            {
                string path = Concrete(pattern);
                bool ok = rule.Target == RuleTarget.Children
                    ? roots.Any(r => PathGuard.IsSameOrInside(path, r))
                    : roots.Any(r => PathGuard.IsStrictlyInside(path, r)) ||
                      items.Any(i => string.Equals(Path.GetDirectoryName(i), Path.GetDirectoryName(path), StringComparison.OrdinalIgnoreCase)
                                     && FileWalker.Matches(Path.GetFileName(path), Path.GetFileName(i)));
                if (!ok) problems.Add($"{rule.Id}: {pattern} -> {path}");
            }
        }
        Assert.Empty(problems);
    }

    [Fact]
    public void RuleIdsAreUniqueAndHighRiskIsNeverPreselected()
    {
        var rules = SystemJunkModule.LoadRules().Rules;
        Assert.Equal(rules.Length, rules.Select(r => r.Id).Distinct().Count());
        Assert.DoesNotContain(rules, r => r.Risk == RiskLevel.High && r.AutoSelect);
        Assert.DoesNotContain(rules, r => r.Risk == RiskLevel.Medium && r.AutoSelect);
    }

    [Fact]
    public void SystemItemsAreRemovableOnlyAsThemselves()
    {
        var remover = new SafeRemover(Roots.System(), RemovalMode.DryRun, null, [], Roots.SystemItems());
        Assert.Equal(RemovalError.OutsideAllowedRoots, remover.Validate(Path.Combine(KnownPaths.Windows, "System32")));
        Assert.Equal(RemovalError.OutsideAllowedRoots, remover.Validate(Path.Combine(KnownPaths.SystemDrive, "Users")));
        Assert.Equal(RemovalError.OutsideAllowedRoots, remover.Validate(Path.Combine(KnownPaths.SystemDrive, "FOUND.000", "file0000.chk")));
    }
}
