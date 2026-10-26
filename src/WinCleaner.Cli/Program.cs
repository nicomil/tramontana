using System.Diagnostics;
using WinCleaner.Core;
using WinCleaner.Modules;
using WinCleaner.Modules.Apps;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Privacy;
using WinCleaner.Modules.Protection;
using WinCleaner.Modules.Helper;

// Command-line front end, to try scans from a terminal.
//   wccli scan <module>                     read only
//   wccli clean <module> [--mode dry|recycle|delete]
//                                           removes the preselected user-level items (dry run by default)
Console.OutputEncoding = System.Text.Encoding.UTF8;

if (args.Length >= 1 && args[0] == "apps")
{
    var watch = Stopwatch.StartNew();
    var programs = InstalledPrograms.All();
    Console.WriteLine($"{programs.Count} programmi ({watch.ElapsedMilliseconds} ms)");
    foreach (var p in programs)
        Console.WriteLine($"  {p.Name,-50} {p.Version,-16} {(p.Source == ProgramSource.Store ? "Store" : p.PerUser ? "utente" : "PC"),-6} {Format.Bytes(p.Size),9} {(p.LastUsedUtc is { } u ? "usato " + UserFilesWalker.Age(u) : ""),-16} {p.InstallLocation}");
    return 0;
}
if (args.Length >= 2 && args[0] == "leftovers")
{
    var programs = InstalledPrograms.All();
    var program = programs.FirstOrDefault(p => p.Name.Contains(args[1], StringComparison.OrdinalIgnoreCase));
    if (program is null) { Console.WriteLine("programma non trovato"); return 1; }
    Console.WriteLine($"{program.Name} ({program.InstallLocation}) · disinstallatore: {ProgramUninstaller.Command(program)}");
    var found = LeftoverFinder.Find(program, programs, uninstalled: args.Contains("--after"));
    foreach (var c in found.Categories)
    {
        Console.WriteLine($"[{c.Title}]");
        foreach (var i in c.Items) Console.WriteLine($"  {(i.AutoSelect ? "[x]" : "[ ]")} {i.Path} {Format.Bytes(i.Size)} {(i.NeedsAdmin ? "[admin]" : "")} {i.Detail}");
    }
    return 0;
}
if (args.Length >= 1 && args[0] == "updates")
{
    var watch = Stopwatch.StartNew();
    var updates = await WingetUpdates.CheckAsync(CancellationToken.None);
    Console.WriteLine($"{updates.Count} aggiornamenti ({watch.ElapsedMilliseconds} ms)");
    foreach (var u in updates) Console.WriteLine($"  {u.Name,-40} {u.Id,-35} {u.InstalledVersion,-16} -> {u.AvailableVersion,-16} {u.Source}");
    return 0;
}

if (args.Length >= 1 && args[0] == "privacy")
{
    var watch = Stopwatch.StartNew();
    var items = PrivacyScanner.Scan();
    Console.WriteLine($"{items.Count} elementi ({watch.ElapsedMilliseconds} ms)");
    foreach (var i in items) Console.WriteLine($"  {(i.AutoSelect ? "[x]" : "[ ]")} {i.Owner,-18} {i.Profile,-14} {i.Kind.Title(),-36} {i.Count,7}{(i.NeedsAdmin ? " [admin]" : "")}");
    foreach (var c in PrivacyScanner.CapabilityUses().Take(8)) Console.WriteLine($"  uso: {c.Capability} {c.App} {c.LastUsedUtc:g}{(c.InUse ? " (in uso)" : "")}");
    return 0;
}
if (args.Length >= 1 && args[0] == "startup")
{
    var watch = Stopwatch.StartNew();
    var items = StartupManager.List();
    Console.WriteLine($"{items.Count} elementi ({watch.ElapsedMilliseconds} ms)");
    foreach (var i in items) Console.WriteLine($"  {(i.Enabled ? "on " : "off")} {i.Kind,-14} {i.Name,-40} {i.Signature?.Status,-9} {i.Signature?.Publisher,-30} {(i.IsBroken ? "ROTTO " : "")}{i.Executable}");
    return 0;
}
if (args.Length >= 1 && args[0] == "protection")
{
    var watch = Stopwatch.StartNew();
    var findings = ProtectionScanner.Scan();
    Console.WriteLine($"{findings.Count} risultati ({watch.ElapsedMilliseconds} ms)");
    foreach (var f in findings) Console.WriteLine($"  {f.Severity,-8} [{f.Category}] {f.Title}: {f.Reason}");
    return 0;
}
if (args.Length >= 1 && args[0] == "monitor")
{
    var monitor = new SystemMonitor();
    monitor.Next();
    await Task.Delay(1000);
    var s = monitor.Next();
    Console.WriteLine($"CPU {s.CpuUsage:P0} · RAM {Format.Bytes(s.MemoryUsed)} di {Format.Bytes(s.MemoryTotal)} · C: {Format.Bytes(s.DiskFree)} liberi · batteria {(s.BatteryLevel is { } b ? b.ToString("P0") : "-")} · acceso da {(int)s.Uptime.TotalHours} ore · {s.ProcessCount} processi");
    return 0;
}

if (args.Length >= 1 && args[0] == "helper-test")
{
    var watch = Stopwatch.StartNew();
    await using var helper = await HelperClient.StartAsync(CancellationToken.None);
    Console.WriteLine($"helper collegato ({watch.ElapsedMilliseconds} ms)");
    var scan = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.ScanSystemJunk }, CancellationToken.None);
    Console.WriteLine($"scansione di sistema: {scan.Ok} {Format.Bytes(scan.Report?.TotalSize ?? 0)} in {scan.Report?.AllItems.Count()} elementi");
    var paths = scan.Report?.AllItems.Take(3).Select(i => i.Path).ToArray() ?? [];
    var dry = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.Remove, Paths = [.. paths, @"C:\Windows\System32\drivers", @"C:\Program Files\WindowsApps\x", @"C:\Users"], Mode = RemovalMode.DryRun }, CancellationToken.None);
    foreach (var o in dry.Outcomes) Console.WriteLine($"  {o.Path}: {(o.Succeeded ? "ok " + Format.Bytes(o.Freed) : o.Error.ToString())}");
    return 0;
}

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
if (args.Contains("--items"))
    foreach (var item in report.AllItems.Take(60))
        Console.WriteLine($"    {(item.AutoSelect ? "[x]" : "[ ]")} {item.DisplayName} {Format.Bytes(item.Size)} · {item.Detail ?? item.Path}");
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
