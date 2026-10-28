using System.Net;
using Tramontana.Core;
using Tramontana.Modules.Protection;
using Tramontana.Modules.Protection.Checks;
using Tramontana.Modules.Protection.Processes;
using Severity = Tramontana.Modules.Protection.Severity;

namespace Tramontana.Tests;

public class ProcessesTests
{
    private static ProcessActivity Activity(int pid, string name, string? path, double cpu, int parent = 1, string? command = null, bool mine = true) =>
        new(new ProcessRecord(pid, parent, name, path, command, DateTime.Now, mine), cpu, 10_000_000, 0, 2);

    [Fact]
    public void LiveSamplerSeesItselfAndMeasuresCpu()
    {
        var sampler = new ProcessSampler();
        sampler.Sample();
        var end = DateTime.Now.AddMilliseconds(400);
        double x = 0;
        while (DateTime.Now < end) x += Math.Sin(x) + 1;
        var me = sampler.Sample().FirstOrDefault(a => a.Process.Pid == Environment.ProcessId);
        Assert.NotNull(me);
        Assert.True(me.Process.IsMine);
        Assert.True(me.Cpu > 0.2, $"cpu {me.Cpu}");
        Assert.True(me.Memory > 0);
        Assert.NotNull(me.Process.Path);
        Assert.True(x > 0);
        Assert.Contains(new SystemConnections().List(), c => c.Pid >= 0);
        Assert.NotEmpty(LoadedModules.Of(Environment.ProcessId));
    }

    [Fact]
    public void MinerFakeSvchostAndOfficeChildAreDangers()
    {
        using var temp = new TempDir();
        string profile = temp.Dir("profile");
        string miner = temp.File(@"profile\AppData\Roaming\xmrig.exe");
        string fakeHost = temp.File(@"profile\AppData\Local\Temp\svchost.exe");
        // Real files outside %TEMP% (the fixture folder itself counts as a dangerous place).
        string excel = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        string chrome = Path.Combine(Environment.SystemDirectory, "calc.exe");
        string ps = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var sample = new List<ProcessActivity>
        {
            Activity(900, "xmrig.exe", miner, 0.95),
            Activity(901, "svchost.exe", fakeHost, 0.0, parent: 1),
            Activity(902, "EXCEL.EXE", excel, 0.1),
            Activity(903, "powershell.exe", ps, 0.0, parent: 902, command: "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
            Activity(904, "chrome.exe", chrome, 0.9),
            Activity(905, "gone.exe", Path.Combine(temp.Path, "gone.exe"), 0.0),
        };
        var connections = new FakeConnections(
            new Connection(900, "TCP", IPAddress.Parse("10.0.0.5"), 50000, IPAddress.Parse("45.67.89.10"), 3333, "ESTABLISHED"),
            new Connection(901, "TCP", IPAddress.Any, 4444, null, 0, "LISTEN"));
        var signatures = new FakeSignatures(new SignatureInfo(SignatureStatus.Signed, "Google LLC"))
            .With(miner, SignatureStatus.Unsigned).With(fakeHost, SignatureStatus.Unsigned).With(excel, SignatureStatus.Signed, "Microsoft Corporation").With(ps, SignatureStatus.Signed, "Microsoft Windows");
        var check = new ProcessesCheck([sample, sample, sample], connections, _ => []);
        var byPid = check.Run(Fake.Context(signatures: signatures, profile: profile)).ToDictionary(f => f.ProcessId!.Value);

        Assert.Equal(Severity.Danger, byPid[900].Severity);
        Assert.Contains("95% di un core", byPid[900].Reason);
        Assert.Contains("mining pool", byPid[900].Reason);
        Assert.Equal(FindingAction.TerminateProcess, byPid[900].Action);
        Assert.Equal(Severity.Danger, byPid[901].Severity);
        Assert.Contains("nome di un processo di Windows", byPid[901].Reason);
        Assert.Contains("In ascolto sulla rete sulle porte 4444", byPid[901].Reason);
        Assert.Equal(Severity.Danger, byPid[903].Severity);
        Assert.Contains("EXCEL.EXE ha avviato powershell.exe", byPid[903].Reason);
        Assert.Contains("base64", byPid[903].Reason);
        Assert.False(byPid.ContainsKey(902));
        Assert.True(byPid[904].Severity == Severity.Warning && byPid[904].Reason.Contains("90% di un core")); // busy but signed, not Microsoft
        Assert.Equal(Severity.Danger, byPid[905].Severity);
        Assert.Contains("cancellato", byPid[905].Reason);
    }

    [Fact]
    public void SpikeIsNotSustainedAndDevelopmentToolsAreQuiet()
    {
        var path = @"C:\Users\dev\.nuget\packages\tool\1.0\tool.exe"; // folder does not exist: not "deleted", just unreadable
        var samples = new List<IReadOnlyList<ProcessActivity>>
        {
            new List<ProcessActivity> { Activity(5, "tool.exe", path, 0.9) },
            new List<ProcessActivity> { Activity(5, "tool.exe", path, 0.1) },
            new List<ProcessActivity> { Activity(5, "tool.exe", path, 0.95) },
        };
        var check = new ProcessesCheck(samples, new FakeConnections(), _ => []);
        var findings = check.Run(Fake.Context(signatures: new FakeSignatures(new SignatureInfo(SignatureStatus.Unsigned, null)).With(path, SignatureStatus.Unsigned))).ToList();
        Assert.DoesNotContain(findings, f => f.Severity > Severity.Info);
    }

    [Fact]
    public void InjectedUnsignedModuleIsDanger()
    {
        using var temp = new TempDir();
        string profile = temp.Dir("profile");
        string dll = temp.File(@"profile\AppData\Local\Temp\hook.dll");
        string explorer = Path.Combine(KnownPaths.Windows, "explorer.exe");
        var sample = new List<ProcessActivity> { Activity(10, "explorer.exe", explorer, 0.0) };
        var signatures = new FakeSignatures().With(dll, SignatureStatus.Unsigned);
        var check = new ProcessesCheck([sample], new FakeConnections(), pid => pid == 10 ? [Path.Combine(KnownPaths.Windows, "system32", "ntdll.dll"), dll] : []);
        var finding = Assert.Single(check.Run(Fake.Context(signatures: signatures, profile: profile)));
        Assert.Equal(Severity.Danger, finding.Severity);
        Assert.Contains("iniezione", finding.Reason);
        Assert.Contains($"Modulo: {dll}", finding.Evidence);
    }

    [Fact]
    public void BusyWatcherNeedsAStreak()
    {
        var source = new FakeProcesses();
        source.Records.Add(new ProcessRecord(77, 1, "hog.exe", @"C:\Tools\hog.exe", null, DateTime.Now, true));
        var cpu = TimeSpan.Zero;
        var watcher = new BusyProcessWatcher(source, new FakeSignatures(new SignatureInfo(SignatureStatus.Unsigned, null)));
        for (int i = 0; i < 4; i++)
        {
            source.CounterTable[77] = new ProcessCounters(cpu, 1, 0, 0, 1);
            cpu += TimeSpan.FromSeconds(1);
            var alert = watcher.Check(samplesForMinute: 3);
            Thread.Sleep(20);
            // first call has no previous sample, streak starts at the second; the alert fires at the third busy sample
            if (i < 3) Assert.Null(alert); else Assert.NotNull(alert);
        }
    }
}
