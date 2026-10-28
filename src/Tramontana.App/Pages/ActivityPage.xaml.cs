using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Tramontana.App.Services;
using Tramontana.Core;
using Tramontana.Modules.Protection;
using Tramontana.Modules.Protection.Checks;
using Tramontana.Modules.Protection.Processes;

namespace Tramontana.App.Pages;

/// <summary>
/// Live view of the processes: CPU, memory and disk per process, the
/// connections, and the Protection verdict next to each one. Refreshed
/// every two seconds while the page is open. Rows are kept per process and
/// updated in place, so the list never flickers or empties between samples.
/// </summary>
public sealed partial class ActivityPage : Page
{
    private sealed class RowView
    {
        public required string Name;
        public required Grid Root;
        public required FontIcon Lead;
        public required TextBlock Stats;
        public required TextBlock Reason;
    }

    private readonly ProcessSampler _sampler = new();
    private readonly List<IReadOnlyList<ProcessActivity>> _history = [];
    private readonly Dictionary<string, SignatureInfo> _signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly ObservableCollection<FrameworkElement> _items = [];
    private readonly Dictionary<int, RowView> _rows = [];
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
        List.ItemsSource = _items;
        var sort = new ComboBox { Width = 160 };
        foreach (var (tag, text) in new[] { ("cpu", "CPU"), ("memory", "Memoria"), ("disk", "Disco"), ("network", "Connessioni") }) sort.Items.Add(new ComboBoxItem { Content = text, Tag = tag });
        sort.SelectedIndex = 0;
        sort.SelectionChanged += (_, _) => { _sort = (string)((ComboBoxItem)sort.SelectedItem).Tag; Render(); };
        Toolbar.Children.Add(sort);
        var mine = new CheckBox { Content = "Solo i miei", IsChecked = true, VerticalAlignment = VerticalAlignment.Center };
        mine.Checked += (_, _) => { _onlyMine = true; Render(); };
        mine.Unchecked += (_, _) => { _onlyMine = false; Render(); };
        Toolbar.Children.Add(mine);
        Toolbar.Children.Add(UI.Button("Gestione attività", (_, _) => Shell.Open("taskmgr.exe"), glyph: ""));
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
        catch (Exception e)
        {
            // A live view must not die silently: the sample is skipped and the reason is in the log.
            OperationLog.Standard.Write($"activity\terror\t{e}");
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

        // The same element per process, moved rather than recreated: a cleared list would be empty for a frame.
        var wanted = new List<FrameworkElement>(list.Count);
        foreach (var a in list)
        {
            if (!_rows.TryGetValue(a.Process.Pid, out var view) || view.Name != a.Process.Name)
                _rows[a.Process.Pid] = view = CreateRow(a);
            UpdateRow(view, a, byPid.GetValueOrDefault(a.Process.Pid));
            wanted.Add(view.Root);
        }
        var wantedSet = new HashSet<FrameworkElement>(wanted);
        for (int i = _items.Count - 1; i >= 0; i--) if (!wantedSet.Contains(_items[i])) _items.RemoveAt(i);
        var present = new HashSet<FrameworkElement>(_items);
        foreach (var e in wanted) if (present.Add(e)) _items.Add(e);
        for (int i = 0; i < wanted.Count; i++)
        {
            int j = _items.IndexOf(wanted[i]);
            if (j != i) _items.Move(j, i);
        }
        var alive = latest.Select(a => a.Process.Pid).ToHashSet();
        foreach (var pid in _rows.Keys.Where(p => !alive.Contains(p)).ToList()) _rows.Remove(pid);
    }

    private RowView CreateRow(ProcessActivity a)
    {
        var lead = new FontIcon { FontSize = 16, Visibility = Visibility.Collapsed, VerticalAlignment = VerticalAlignment.Center };
        var stats = UI.Caption("");
        var reason = UI.Caption("");
        reason.Visibility = Visibility.Collapsed;
        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = $"{a.Process.Name}  ({a.Process.Pid})", TextTrimming = TextTrimming.CharacterEllipsis });
        texts.Children.Add(stats);
        texts.Children.Add(reason);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
        if (a.Process.Path is { } p) actions.Children.Add(UI.Button("Mostra", (_, _) => Shell.Reveal(p)));
        if (a.Process.IsMine && a.Process.Pid != Environment.ProcessId)
            actions.Children.Add(UI.Button("Termina", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync($"Terminare {a.Process.Name}?", $"Il processo {a.Process.Pid} verrà chiuso. Se riparte da solo, cerca il suo elemento di avvio in Protezione.", "Termina", destructive: true)) return;
                try { using var process = System.Diagnostics.Process.GetProcessById(a.Process.Pid); process.Kill(); OperationLog.Standard.Write($"process\tkill\t{a.Process.Pid}\t{a.Process.Path}"); }
                catch (Exception e) { UI.Show(Bar, "Non terminato", e.Message, InfoBarSeverity.Error); }
            }));
        var grid = new Grid { ColumnSpacing = 12, Padding = new Thickness(4, 6, 4, 6) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.Children.Add(lead);
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);
        Grid.SetColumn(actions, 2);
        grid.Children.Add(actions);
        return new RowView { Name = a.Process.Name, Root = grid, Lead = lead, Stats = stats, Reason = reason };
    }

    private void UpdateRow(RowView view, ProcessActivity a, int connections)
    {
        _findings.TryGetValue(a.Process.Pid, out var finding);
        if (finding is not null)
        {
            var (glyph, brush) = finding.Severity switch
            {
                Severity.Danger => ("", "SystemFillColorCriticalBrush"),
                Severity.Warning => ("", "SystemFillColorCautionBrush"),
                _ => ("", "SystemFillColorAttentionBrush"),
            };
            view.Lead.Glyph = glyph;
            view.Lead.Foreground = UI.Brush(brush);
            view.Lead.Visibility = Visibility.Visible;
            ToolTipService.SetToolTip(view.Lead, finding.Reason);
            view.Reason.Text = finding.Reason;
            view.Reason.Visibility = Visibility.Visible;
        }
        else
        {
            view.Lead.Visibility = Visibility.Collapsed;
            view.Reason.Visibility = Visibility.Collapsed;
        }
        string signature = a.Process.Path is { } path && _signatures.TryGetValue(path, out var s)
            ? s.Status switch { SignatureStatus.Signed => s.IsMicrosoft ? "Microsoft" : s.Publisher ?? "firmato", SignatureStatus.Unsigned => "non firmato", SignatureStatus.Invalid => "firma non valida", SignatureStatus.Untrusted => (s.Publisher ?? "firmato") + " (editore non riconosciuto)", _ => "" }
            : "";
        view.Stats.Text = $"CPU {a.Cpu:P0} · {Format.Bytes(a.Memory)} · disco {Format.Bytes((long)a.DiskBytesPerSecond)}/s · {connections} connessioni · {signature}";
    }
}
