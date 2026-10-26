using System.Net;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// What is running right now, judged the way an expert reads Task Manager:
/// who it is, where it lives, what its command line does, what it does with
/// the CPU and the network, and which DLLs it carries around.
/// </summary>
public sealed class ProcessesCheck : IProtectionCheck
{
    public string Id => "processes";
    public string Title => "Processi in esecuzione";

    private readonly IReadOnlyList<IReadOnlyList<Processes.ProcessActivity>>? _samples;
    private readonly Processes.IConnectionSource? _connections;
    private readonly Func<int, List<string>>? _modules;
    private readonly int _intervals;
    private readonly TimeSpan _interval;

    /// <summary>Live sampling, or fixed samples for tests.</summary>
    public ProcessesCheck(IReadOnlyList<IReadOnlyList<Processes.ProcessActivity>>? samples = null, Processes.IConnectionSource? connections = null,
        Func<int, List<string>>? modules = null, int intervals = 3, TimeSpan? interval = null)
    {
        _samples = samples;
        _connections = connections;
        _modules = modules;
        _intervals = intervals;
        _interval = interval ?? TimeSpan.FromSeconds(1);
    }

    /// <summary>Names a process may only carry when it comes from System32 (and, for svchost, from services.exe).</summary>
    private static readonly Dictionary<string, string?> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = "services.exe", ["lsass.exe"] = "wininit.exe", ["csrss.exe"] = null, ["winlogon.exe"] = null, ["wininit.exe"] = null,
        ["services.exe"] = "wininit.exe", ["smss.exe"] = null, ["explorer.exe"] = null, ["RuntimeBroker.exe"] = "svchost.exe", ["dllhost.exe"] = null,
        ["taskhostw.exe"] = "svchost.exe", ["spoolsv.exe"] = "services.exe", ["conhost.exe"] = null, ["dwm.exe"] = "winlogon.exe", ["fontdrvhost.exe"] = null,
        ["sihost.exe"] = "svchost.exe", ["ctfmon.exe"] = null, ["SearchHost.exe"] = null, ["ShellExperienceHost.exe"] = null, ["StartMenuExperienceHost.exe"] = null,
        ["MsMpEng.exe"] = "services.exe", ["SecurityHealthService.exe"] = "services.exe", ["audiodg.exe"] = "svchost.exe", ["WmiPrvSE.exe"] = "svchost.exe",
    };

    private static readonly string[] OfficeAndBrowsers = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "acrord32.exe", "acrobat.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
    private static readonly string[] Spawned = ["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe"];
    private static readonly HashSet<int> SuspiciousPorts = [3333, 4444, 5555, 6666, 6667, 6697, 7777, 8333, 9999, 14433, 14444, 1337, 31337, 45560];
    private static readonly HashSet<int> CommonPorts = [80, 443, 53, 123, 993, 995, 587, 465, 22, 5222, 5223, 3478, 8080, 8443, 1900, 5353, 67, 68, 137, 138, 139, 445, 3389];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var samples = _samples ?? Collect();
        if (samples.Count == 0) yield break;
        var latest = samples[^1];
        var connections = (_connections ?? new Processes.SystemConnections()).List().GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.ToList());
        var byPid = latest.ToDictionary(a => a.Process.Pid, a => a.Process);
        var modules = _modules ?? Processes.LoadedModules.Of;

        foreach (var activity in latest)
        {
            var process = activity.Process;
            if (process.Pid is 0 or 4) continue;
            var reasons = new List<string>();
            var evidence = new List<string> { $"PID {process.Pid}, avviato {process.Started?.ToString("g") ?? "?"}" };
            var severity = Severity.Ok;
            void Add(Severity s, string reason) { reasons.Add(reason); if (s > severity) severity = s; }
            byPid.TryGetValue(process.ParentPid, out var parent);
            if (parent is not null) evidence.Add($"Avviato da {parent.Name} ({parent.Pid})");
            if (process.CommandLine is not null) evidence.Add($"Comando: {Trim(process.CommandLine)}");
            string? path = process.Path;
            SignatureInfo? signature = null;
            if (path is not null)
            {
                evidence.Add($"Percorso: {path}");
                signature = context.Signatures.Check(path);
                if (signature.Status == SignatureStatus.Missing) signature = null;
                if (signature?.Publisher is not null) evidence.Add($"Firmato da: {signature.Publisher}");
                bool microsoft = signature?.IsMicrosoft == true;
                if (signature?.Status == SignatureStatus.Invalid) Add(Severity.Danger, "La firma del programma non è valida: file modificato");
                else if (signature?.Status == SignatureStatus.Unsigned && !LooksLikeDevelopment(path) && !IsPackagedApp(path))
                {
                    if (Suspicion.IsHiddenFolder(path) || Suspicion.IsBareDataFolder(path, context.UserProfile)) Add(Severity.Warning, "Programma senza firma in una cartella dove i programmi non vivono");
                    else Add(Severity.Info, "Programma senza firma digitale");
                }
                if (Suspicion.IsInDangerousFolder(path, context.UserProfile)) Add(Severity.Danger, $"Gira da una cartella temporanea o condivisa ({Path.GetDirectoryName(path)})");
                // A missing file in an existing folder is a deleted executable; a missing folder is just one we cannot read.
                if (!File.Exists(path) && Directory.Exists(Path.GetDirectoryName(path))) Add(Severity.Danger, "L'eseguibile è stato cancellato mentre il processo gira: tecnica per nascondersi");
                if (!microsoft && SystemNames.TryGetValue(process.Name, out var expectedParent))
                {
                    if (!Suspicion.IsInWindows(path)) Add(Severity.Danger, $"Ha il nome di un processo di Windows ma non viene da System32 ({Path.GetDirectoryName(path)})");
                    else if (expectedParent is not null && parent is not null && !parent.Name.Equals(expectedParent, StringComparison.OrdinalIgnoreCase) && !microsoft)
                        Add(Severity.Warning, $"{process.Name} avviato da {parent.Name} invece che da {expectedParent}");
                    else if (expectedParent is not null && parent is not null && !parent.Name.Equals(expectedParent, StringComparison.OrdinalIgnoreCase) && process.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                        Add(Severity.Danger, $"svchost.exe avviato da {parent.Name} invece che da services.exe: tipico dei malware che si travestono");
                }
                if (!microsoft && process.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase) && latest.Count(a => a.Process.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)) > 1)
                    Add(Severity.Danger, "Più di un lsass.exe in esecuzione");
            }
            foreach (var r in Suspicion.CommandLineReasons(process.CommandLine)) Add(Severity.Danger, r);
            if (parent is not null && OfficeAndBrowsers.Contains(parent.Name, StringComparer.OrdinalIgnoreCase) && Spawned.Contains(process.Name, StringComparer.OrdinalIgnoreCase))
                Add(Severity.Danger, $"{parent.Name} ha avviato {process.Name}: un documento o una pagina sta eseguendo comandi");

            // Sustained CPU: busy in every sample, not just a spike.
            var history = samples.Select(s => s.FirstOrDefault(a => a.Process.Pid == process.Pid)?.Cpu).ToList();
            bool sustained = history.All(h => h is >= 0.8);
            var procConnections = connections.GetValueOrDefault(process.Pid) ?? [];
            var remotePorts = procConnections.Where(c => c.Remote is not null).Select(c => c.RemotePort).ToHashSet();
            bool miningPort = remotePorts.Overlaps(SuspiciousPorts);
            bool microsoftSigned = signature?.IsMicrosoft == true;
            if (sustained && !microsoftSigned)
            {
                Add(miningPort ? Severity.Danger : Severity.Warning, $"Usa il {history[^1]!.Value * 100:0}% di un core da {(samples.Count - 1) * _interval.TotalSeconds:0} secondi");
                evidence.Add("CPU nei campioni: " + string.Join(", ", history.Select(h => $"{(h ?? 0) * 100:0}%")));
            }
            if (miningPort)
                Add(Severity.Warning, $"Collegato a porte usate da mining pool, bot IRC o shell remote ({string.Join(", ", remotePorts.Intersect(SuspiciousPorts).Order())})");
            var listening = procConnections.Where(c => c.Protocol == "TCP" && c.ListensOnAllInterfaces).Select(c => c.LocalPort).Distinct().Order().ToList();
            if (listening.Count > 0 && !microsoftSigned && (signature is null || signature.Status != SignatureStatus.Signed || Suspicion.IsInDangerousFolder(path ?? "", context.UserProfile)))
                Add(Severity.Warning, $"In ascolto sulla rete sulle porte {string.Join(", ", listening.Take(6))}: accetta connessioni da altri computer");
            var rawRemote = procConnections.Where(c => c.Remote is not null && c.IsEstablished && !IsPrivate(c.Remote!) && !CommonPorts.Contains(c.RemotePort)).ToList();
            if (rawRemote.Count > 0 && (signature is null || signature.Status != SignatureStatus.Signed))
                Add(Severity.Warning, $"Programma senza firma collegato a {rawRemote[0].Remote}:{rawRemote[0].RemotePort}" + (rawRemote.Count > 1 ? $" e altri {rawRemote.Count - 1}" : ""));
            evidence.AddRange(procConnections.Where(c => c.Remote is not null || c.IsListening).Take(8).Select(c => $"{c.Protocol} {c.Local}:{c.LocalPort}{(c.Remote is null ? "" : $" → {c.Remote}:{c.RemotePort}")} {c.State}"));

            // Unsigned DLLs from user folders inside a signed process: injection.
            if (process.IsMine && (microsoftSigned || signature?.Status == SignatureStatus.Signed))
            {
                List<string> loaded;
                try { loaded = modules(process.Pid); } catch (Exception) { loaded = []; }
                foreach (var module in loaded.Where(Processes.LoadedModules.IsOutsidePrograms).Where(m => m.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).Take(50))
                {
                    if (LooksLikeDevelopment(module) || module.Contains(@"\AppData\Local\Microsoft\", StringComparison.OrdinalIgnoreCase)) continue;
                    var ms = context.Signatures.Check(module);
                    if (ms.Status is SignatureStatus.Signed or SignatureStatus.Missing) continue;
                    if (Suspicion.IsInDangerousFolder(module, context.UserProfile) || Suspicion.IsBareDataFolder(module, context.UserProfile) || Suspicion.IsHiddenFolder(module))
                    {
                        Add(Severity.Danger, $"Ha caricato una libreria senza firma da {Path.GetDirectoryName(module)}: possibile iniezione");
                        evidence.Add($"Modulo: {module}");
                    }
                }
            }

            if (reasons.Count == 0) continue;
            if (signature?.Publisher is not null && context.TrustedPublishers.Contains(signature.Publisher) && severity < Severity.Danger) continue;
            yield return new Finding($"process|{process.Pid}|{path ?? process.Name}", Categories.Processes, $"{process.Name} (PID {process.Pid})",
                string.Join(". ", reasons) + ".", severity)
            {
                Path = path, Evidence = [.. evidence], Publisher = signature?.Publisher, ProcessId = process.Pid,
                Action = process.IsMine ? FindingAction.TerminateProcess : FindingAction.None,
            };
        }
    }

    private List<IReadOnlyList<Processes.ProcessActivity>> Collect()
    {
        var sampler = new Processes.ProcessSampler();
        sampler.Sample();
        var samples = new List<IReadOnlyList<Processes.ProcessActivity>>();
        for (int i = 0; i < Math.Max(_intervals, 1); i++)
        {
            Thread.Sleep(_interval);
            samples.Add(sampler.Sample());
        }
        return samples;
    }

    /// <summary>Store apps are signed as a package, not file by file.</summary>
    internal static bool IsPackagedApp(string path) => path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Tool chains and package caches (node_modules, .nuget, pip…) are rarely signed.</summary>
    internal static bool LooksLikeDevelopment(string path) =>
        path.Contains(@"\node_modules\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.nuget\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\.cargo\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.rustup\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\site-packages\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.vscode\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\.cursor\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\dotnet\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\bin\Debug\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\bin\Release\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\.gradle\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\go\pkg\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\Programs\Python\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.m2\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\VBCSCompiler\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\AnalyzerAssemblyLoader\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\MSBuild\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\.dotnet\", StringComparison.OrdinalIgnoreCase);

    private static bool IsPrivate(IPAddress address)
    {
        var b = address.GetAddressBytes();
        if (b.Length != 4) return true;
        return b[0] == 10 || b[0] == 127 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 169 && b[1] == 254) || b[0] == 0;
    }

    private static string Trim(string s) => s.Length > 300 ? s[..300] + "…" : s;
}

/// <summary>Notices a non-Microsoft process that keeps a core busy for over a minute (for the tray icon).</summary>
public sealed class BusyProcessWatcher(Processes.IProcessSource? source = null, ISignatureEvaluator? signatures = null)
{
    public sealed record Alert(string Name, int Pid, double Cpu, string Path);

    private readonly Processes.ProcessSampler _sampler = new(source);
    private readonly ISignatureEvaluator _signatures = signatures ?? new SystemSignatures();
    private readonly Dictionary<int, int> _streaks = [];
    private readonly Lock _lock = new();

    /// <summary>Called every few seconds; <paramref name="samplesForMinute"/> consecutive busy samples make the alert.</summary>
    public Alert? Check(int samplesForMinute = 20)
    {
        lock (_lock)
        {
            var sample = _sampler.Sample();
            Alert? alert = null;
            var next = new Dictionary<int, int>();
            foreach (var activity in sample.Where(a => a.Cpu >= 0.8 && a.Process.Path is not null))
            {
                int streak = _streaks.GetValueOrDefault(activity.Process.Pid) + 1;
                next[activity.Process.Pid] = streak;
                if (streak < samplesForMinute) continue;
                var signature = _signatures.Check(activity.Process.Path!);
                if (signature.IsMicrosoft) continue;
                if (alert is null || activity.Cpu > alert.Cpu) alert = new Alert(activity.Process.Name, activity.Process.Pid, activity.Cpu, activity.Process.Path!);
            }
            _streaks.Clear();
            foreach (var (pid, streak) in next) _streaks[pid] = streak;
            return alert;
        }
    }
}
