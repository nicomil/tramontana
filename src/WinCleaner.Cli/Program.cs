using System.Diagnostics;
using WinCleaner.Core;
using WinCleaner.Modules;

// Command-line front end, to try scans from a terminal.
//   wccli scan <module>                     read only
//   wccli clean <module> [--mode dry|recycle|delete]
//                                           removes the preselected user-level items (dry run by default)
Console.OutputEncoding = System.Text.Encoding.UTF8;

if (args.Length >= 1 && args[0] == "lens")
{
    string root = args.Length > 1 && !args[1].StartsWith("--") ? args[1] : KnownPaths.SystemDrive;
    var counter = new ScanCounter();
    var watch = Stopwatch.StartNew();
    int depthArg = Array.IndexOf(args, "--depth"); var tree = new SpaceLensScanner { ParallelDepth = depthArg > 0 ? int.Parse(args[depthArg + 1]) : 20 }.Scan(root, counter);
    var (total, free) = SpaceLensScanner.DriveSpace(root);
    Console.WriteLine($"{tree.Path}: {Format.Bytes(tree.Size)} in {counter.Snapshot.Files} file ({watch.ElapsedMilliseconds} ms). Disco: {Format.Bytes(total - free)} usati di {Format.Bytes(total)}");
    void Print(DiskNode node, int depth)
    {
        foreach (var child in node.Children.Take(depth == 0 ? 12 : 4))
        {
            Console.WriteLine($"{new string(' ', depth * 2 + 2)}{child.Name,-40} {Format.Bytes(child.Size),10}{(child.IsUnreadable ? " (illeggibile)" : "")}");
            if (depth < 1 && child.IsDirectory) Print(child, depth + 1);
        }
    }
    Print(tree, 0);
    return 0;
}

if (args.Length < 2 || args[0] is not ("scan" or "clean"))
{
    Console.WriteLine("uso: wccli scan|clean <modulo> [--mode dry|recycle|delete]");
    Console.WriteLine("moduli: " + string.Join(", ", ModuleCatalog.All().Select(m => m.Id)));
    return 1;
}

var module = ModuleCatalog.Find(args[1]);
if (module is null)
{
    Console.Error.WriteLine($"modulo sconosciuto: {args[1]}");
    return 1;
}

var clock = Stopwatch.StartNew();
var report = await module.ScanAsync(null, CancellationToken.None);
Console.WriteLine($"{module.Title}: {Format.Bytes(report.TotalSize)} in {report.AllItems.Count()} elementi ({clock.ElapsedMilliseconds} ms)");
foreach (var group in report.Categories.GroupBy(c => c.Group))
{
    Console.WriteLine($"[{group.Key}]");
    foreach (var category in group)
    {
        int auto = category.Items.Count(i => i.AutoSelect);
        Console.WriteLine($"  {category.Title,-48} {Format.Bytes(category.TotalSize),10}  {category.Items.Count,5} elem. ({auto} presel.){(category.Items.Any(i => i.NeedsAdmin) ? " [admin]" : "")}");
    }
}
foreach (var note in report.Notes) Console.WriteLine("nota: " + note);
foreach (var path in report.Unreadable.Take(10)) Console.WriteLine("illeggibile: " + path);

if (args[0] == "clean")
{
    var mode = RemovalMode.DryRun;
    int index = Array.IndexOf(args, "--mode");
    if (index >= 0 && index + 1 < args.Length)
        mode = args[index + 1] switch { "recycle" => RemovalMode.Recycle, "delete" => RemovalMode.Delete, _ => RemovalMode.DryRun };
    var chosen = report.AllItems.Where(i => i.AutoSelect && !i.NeedsAdmin).ToList();
    clock.Restart();
    var outcomes = Cleaner.CleanUserItems(module, chosen, mode);
    long freed = outcomes.Sum(o => o.Freed);
    Console.WriteLine($"{mode}: {Format.Bytes(freed)} liberati, {outcomes.Count(o => o.Succeeded)} ok, {outcomes.Count(o => !o.Succeeded)} errori, {outcomes.Sum(o => o.InUse)} in uso ({clock.ElapsedMilliseconds} ms)");
    foreach (var error in outcomes.Where(o => !o.Succeeded).GroupBy(o => o.Error))
        Console.WriteLine($"  {error.Key}: {error.Count()} (es. {error.First().Path} {error.First().Message})");
}
return 0;
