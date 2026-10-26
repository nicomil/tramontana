using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Protection;
using WinCleaner.Modules.Protection.Checks;
using WinCleaner.Modules.Protection.Processes;

namespace WinCleaner.App.Pages;

/// <summary>
/// Live view of the processes: CPU, memory and disk per process, the
/// connections, and the Protection verdict next to each one. Refreshed
/// every two seconds while the page is open.
/// </summary>
public sealed partial class ActivityPage : Page
{
    private readonly ProcessSampler _sampler = new();
    private readonly List<IReadOnlyList<ProcessActivity>> _history = [];
    private readonly Dictionary<string, SignatureInfo> _signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private IReadOnlyList<Connection> _connections = [];
    private Dictionary<int, Finding> _findings = [];
    private string _sort = "cpu";
    private bool _onlyMine = true;
    private bool _busy;
    private int _ticks;

    public ActivityPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Disabled;
        TitleText.Text = "Attività";
        DescriptionText.Text = "Chi usa CPU, memoria, disco e rete adesso, con il giudizio di Protezione accanto a ogni processo. 100% = un core intero.";
        var sort = new ComboBox { Width = 160 };
        foreach (var (tag, text) in new[] { ("cpu", "CPU"), ("memory", "Memoria"), ("disk", "Disco"), ("network", "Connessioni") }) sort.Items.Add(new ComboBoxItem { Content = text, Tag = tag });
        sort.SelectedIndex = 0;
        sort.SelectionChanged += (_, _) => { _sort = (string)((ComboBoxItem)sort.SelectedItem).Tag; Render(); };
        Toolbar.Children.Add(sort);
        var mine = new CheckBox { Content = "Solo i miei", IsChecked = true, VerticalAlignment = VerticalAlignment.Center };
        mine.Checked += (_, _) => { _onlyMine = true; Render(); };
        mine.Unchecked += (_, _) => { _onlyMine = false; Render(); };
        Toolbar.Children.Add(mine);
        Toolbar.Children.Add(UI.Button("Gestione attività", (_, _) => Shell.Open("taskmgr.exe"), glyph: ""));
        Loaded += (_, _) => { _sampler.Sample(); _timer.Tick += async (_, _) => await TickAsync(); _timer.Start(); };
        Unloaded += (_, _) => _timer.Stop();
    }

    private IReadOnlyList<ProcessActivity> Latest => _history.Count == 0 ? [] : _history[^1];

    private async Task TickAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            bool refreshConnections = _ticks++ % 5 == 0;
            var signatures = _signatures;
            var (sample, connections, findings) = await Task.Run(() =>
            {
                var sample = _sampler.Sample();
                var connections = refreshConnections ? new SystemConnections().List() : null;
                var evaluator = new SystemSignatures();
                lock (signatures)
                    foreach (var a in sample)
                        if (a.Process.Path is { } path && !signatures.ContainsKey(path)) signatures[path] = evaluator.Check(path);
                var history = new List<IReadOnlyList<ProcessActivity>>(_history) { sample };
                if (history.Count > 3) history.RemoveRange(0, history.Count - 3);
                var check = new ProcessesCheck(history, new FakeConnections([.. connections ?? _connections]), interval: TimeSpan.FromSeconds(2));
                var found = check.Run(new CheckContext { Startup = [], Signatures = new CachedSignatures(signatures) }).ToList();
                return (sample, connections, found);
            });
            _history.Add(sample);
            if (_history.Count > 3) _history.RemoveRange(0, _history.Count - 3);
            if (connections is not null) _connections = connections;
            _findings = findings.Where(f => f.ProcessId is not null).GroupBy(f => f.ProcessId!.Value).ToDictionary(g => g.Key, g => g.First());
            foreach (var f in findings.Where(f => f.ProcessId is null))
            {
                var pid = int.TryParse(f.Id.Split('|')[1], out var p) ? p : -1;
                if (pid > 0) _findings.TryAdd(pid, f);
            }
            Render();
        }
        finally { _busy = false; }
    }

    private void Render()
    {
        var latest = Latest;
        var byPid = _connections.GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.Count());
        var rows = latest.Where(a => !_onlyMine || a.Process.IsMine);
        rows = _sort switch
        {
            "memory" => rows.OrderByDescending(a => a.Memory),
            "disk" => rows.OrderByDescending(a => a.DiskBytesPerSecond),
            "network" => rows.OrderByDescending(a => byPid.GetValueOrDefault(a.Process.Pid)),
            _ => rows.OrderByDescending(a => a.Cpu),
        };
        var list = rows.Take(80).ToList();
        int problems = _findings.Values.Count(f => f.Severity >= Severity.Warning);
        StatusText.Text = $"{latest.Count(a => !_onlyMine || a.Process.IsMine)} processi" + (problems > 0 ? $" · {problems} da controllare" : "");
        List.Items.Clear();
        foreach (var a in list) List.Items.Add(Row(a, byPid.GetValueOrDefault(a.Process.Pid)));
    }

    private FrameworkElement Row(ProcessActivity a, int connections)
    {
        _findings.TryGetValue(a.Process.Pid, out var finding);
        FrameworkElement? lead = null;
        if (finding is not null)
        {
            var (glyph, brush) = finding.Severity switch
            {
                Severity.Danger => ("", "SystemFillColorCriticalBrush"),
                Severity.Warning => ("", "SystemFillColorCautionBrush"),
                _ => ("", "SystemFillColorAttentionBrush"),
            };
            lead = new FontIcon { Glyph = glyph, FontSize = 16, Foreground = UI.Brush(brush) };
            ToolTipService.SetToolTip(lead, finding.Reason);
        }
        string signature = a.Process.Path is { } path && _signatures.TryGetValue(path, out var s)
            ? s.Status switch { SignatureStatus.Signed => s.IsMicrosoft ? "Microsoft" : s.Publisher ?? "firmato", SignatureStatus.Unsigned => "non firmato", SignatureStatus.Invalid => "firma non valida", _ => "" }
            : "";
        string stats = $"CPU {a.Cpu:P0} · {Format.Bytes(a.Memory)} · disco {Format.Bytes((long)a.DiskBytesPerSecond)}/s · {connections} connessioni · {signature}";
        var actions = new List<FrameworkElement>();
        if (a.Process.Path is { } p) actions.Add(UI.Button("Mostra", (_, _) => Shell.Reveal(p)));
        if (a.Process.IsMine && a.Process.Pid != Environment.ProcessId)
            actions.Add(UI.Button("Termina", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync($"Terminare {a.Process.Name}?", $"Il processo {a.Process.Pid} verrà chiuso. Se riparte da solo, cerca il suo elemento di avvio in Protezione.", "Termina", destructive: true)) return;
                try { using var process = System.Diagnostics.Process.GetProcessById(a.Process.Pid); process.Kill(); OperationLog.Standard.Write($"process\tkill\t{a.Process.Pid}\t{a.Process.Path}"); }
                catch (Exception e) { UI.Show(Bar, "Non terminato", e.Message, InfoBarSeverity.Error); }
            }));
        var row = UI.Row(lead, $"{a.Process.Name}  ({a.Process.Pid})", stats + (finding is null ? "" : "\n" + finding.Reason), [.. actions]);
        return row;
    }
}
