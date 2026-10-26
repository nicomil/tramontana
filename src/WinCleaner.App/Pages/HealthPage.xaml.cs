using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Apps;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Protection;

namespace WinCleaner.App.Pages;

/// <summary>
/// One-click check of the whole PC, built on the other screens' states.
/// Only safe, preselected user junk is cleaned from here, after a
/// confirmation; everything else links to its screen for review.
/// </summary>
public sealed partial class HealthPage : Page
{
    private static bool _running;

    public HealthPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e) => Render();

    private static AppState S => AppState.Current;

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (_running) return;
        _running = true;
        RunButton.IsEnabled = false;
        Ring.IsActive = true;
        ResultBar.IsOpen = false;
        Headline.Text = "Controllo in corso…";
        try
        {
            var junk = S.Modules["system-junk"].ScanAsync();
            var bin = S.Modules["recycle-bin"].ScanAsync();
            var protection = ProtectionActions.ScanAsync().ContinueWith(t => (IReadOnlyList<Finding>)t.Result);
            var startup = Task.Run(() => (IReadOnlyList<StartupItem>)StartupManager.List());
            var updates = Task.Run(async () =>
            {
                try { return await WingetUpdates.CheckAsync(CancellationToken.None); }
                catch (Exception) { return (IReadOnlyList<AvailableUpdate>?)null; }
            });
            await Task.WhenAll(junk, bin);
            Render();
            S.Findings = await protection;
            Render();
            S.Startup = await startup;
            Render();
            S.Updates = await updates;
            S.Settings.LastHealthCheck = DateTime.Now;
            S.Settings.Save();
        }
        finally
        {
            _running = false;
            RunButton.IsEnabled = true;
            Ring.IsActive = false;
            Render();
        }
    }

    /// <summary>What "Pulisci ora" removes: the preselected user-level junk.</summary>
    private static List<ScanItem> SafeJunk() =>
        S.Modules["system-junk"].SelectedItems().Where(i => !i.NeedsAdmin && i.Risk == RiskLevel.Low).ToList();

    private void Render()
    {
        var last = S.Settings.LastHealthCheck;
        Headline.Text = _running ? "Controllo in corso…" : last is null ? "Controlla tutto il PC in un clic" : $"Ultimo controllo: {last:dddd d MMMM, HH:mm}";
        RunLabel.Text = last is null ? "Avvia il controllo" : "Controlla di nuovo";
        Cards.Children.Clear();

        // Cleanup
        var junkState = S.Modules["system-junk"];
        var binState = S.Modules["recycle-bin"];
        long junk = SafeJunk().Sum(i => i.Size);
        long bins = binState.Report?.TotalSize ?? 0;
        var cleanButton = new Button { Content = "Pulisci ora", Style = (Style)Application.Current.Resources["AccentButtonStyle"], IsEnabled = junk > 0 && !junkState.IsBusy };
        cleanButton.Click += async (_, _) => await CleanNowAsync();
        Cards.Children.Add(Card("", "Pulizia",
            junkState.Report is null ? "Non ancora controllata" : junk > 0 ? $"{Format.Bytes(junk)} da liberare" : "Niente da pulire",
            binState.Report is null ? "File temporanei, cache e log." : bins > 0 ? $"Nel Cestino: {Format.Bytes(bins)}" : "Il Cestino è vuoto.",
            junk > 0 ? Status.Action : Status.Ok, cleanButton, Link("Rivedi", "system-junk")));

        // Protection
        var findings = S.Findings;
        int danger = findings?.Count(f => f.Severity == Severity.Danger) ?? 0;
        int warnings = findings?.Count(f => f.Severity == Severity.Warning) ?? 0;
        Cards.Children.Add(Card("", "Protezione",
            findings is null ? "Non ancora controllata" : danger + warnings == 0 ? "Nessun problema" : $"{danger + warnings} da controllare",
            findings is null ? "Difese di Windows, avvio, estensioni, rete." : danger > 0 ? $"{danger} problemi importanti" : "Difese di Windows attive.",
            findings is null ? Status.None : danger > 0 ? Status.Danger : warnings > 0 ? Status.Action : Status.Ok, Link("Vedi", "protection")));

        // Updates
        var updates = S.Updates;
        Cards.Children.Add(Card("", "Aggiornamenti",
            updates is null ? "Non ancora controllati" : updates.Count == 0 ? "Tutto aggiornato" : $"{updates.Count} aggiornamenti",
            updates is null ? "Programmi con aggiornamenti tramite winget." : updates.Count == 0 ? "I programmi installati sono all'ultima versione." : string.Join(", ", updates.Take(3).Select(u => u.Name)),
            updates is null ? Status.None : updates.Count > 0 ? Status.Action : Status.Ok, Link("Aggiorna", "updates")));

        // Startup and memory
        var startup = S.Startup;
        var snapshot = SystemMonitor.Snapshot();
        Cards.Children.Add(Card("", "Prestazioni",
            startup is null ? "Non ancora controllate" : $"{startup.Count(s => s.Enabled)} programmi all'avvio",
            $"Memoria usata: {snapshot.MemoryUsage:P0} di {Format.Bytes(snapshot.MemoryTotal)}" + (startup?.Count(s => s.IsBroken) is > 0 and var broken ? $" · {broken} voci rotte" : ""),
            startup is null ? Status.None : startup.Count(s => s.Enabled) > 12 ? Status.Action : Status.Ok, Link("Avvio automatico", "startup"), Link("Manutenzione", "maintenance")));

        // Disk
        double used = snapshot.DiskUsage;
        var bar = new ProgressBar { Value = used * 100, Maximum = 100, Margin = new Thickness(0, 6, 0, 0) };
        Cards.Children.Add(Card("", "Disco",
            $"{Format.Bytes(snapshot.DiskFree)} liberi",
            $"su {Format.Bytes(snapshot.DiskTotal)} dell'unità {KnownPaths.SystemDrive.TrimEnd('\\')}",
            used > 0.9 ? Status.Danger : used > 0.8 ? Status.Action : Status.Ok, bar, Link("Analisi disco", "space-lens")));
    }

    private enum Status { None, Ok, Action, Danger }

    private static FrameworkElement Link(string text, string tag)
    {
        var button = new HyperlinkButton { Content = text, Padding = new Thickness(4) };
        button.Click += (_, _) => App.Window?.Navigate(tag);
        return button;
    }

    private static Border Card(string glyph, string title, string headline, string detail, Status status, params FrameworkElement[] actions)
    {
        var res = Application.Current.Resources;
        var color = status switch
        {
            Status.Ok => (Brush)res["SystemFillColorSuccessBrush"],
            Status.Action => (Brush)res["SystemFillColorCautionBrush"],
            Status.Danger => (Brush)res["SystemFillColorCriticalBrush"],
            _ => (Brush)res["TextFillColorTertiaryBrush"],
        };
        var panel = new StackPanel { Spacing = 6 };
        var header = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        header.Children.Add(new FontIcon { Glyph = glyph, FontSize = 20, Foreground = (Brush)res["AccentTextFillColorPrimaryBrush"] });
        header.Children.Add(new TextBlock { Text = title, Style = (Style)res["BodyStrongTextBlockStyle"], VerticalAlignment = VerticalAlignment.Center });
        header.Children.Add(new Border { Width = 8, Height = 8, CornerRadius = new CornerRadius(4), Background = color, VerticalAlignment = VerticalAlignment.Center });
        panel.Children.Add(header);
        panel.Children.Add(new TextBlock { Text = headline, Style = (Style)res["SubtitleTextBlockStyle"], TextTrimming = TextTrimming.CharacterEllipsis });
        panel.Children.Add(new TextBlock { Text = detail, Style = (Style)res["Caption"], MaxLines = 2, TextTrimming = TextTrimming.CharacterEllipsis });
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 0, 0) };
        foreach (var a in actions)
        {
            if (a is ProgressBar) panel.Children.Add(a);
            else row.Children.Add(a);
        }
        panel.Children.Add(row);
        return new Border { Style = (Style)res["Card"], Child = panel, Margin = new Thickness(6) };
    }

    private async Task CleanNowAsync()
    {
        var items = SafeJunk();
        if (items.Count == 0) return;
        if (!await Dialogs.ConfirmAsync("Pulire ora?",
                $"Verranno spostati nel Cestino {items.Count} elementi ({Format.Bytes(items.Sum(i => i.Size))}): file temporanei e cache che si ricreano da soli. Gli elementi di sistema e quelli da controllare restano in «Pulizia sistema».",
                "Pulisci")) return;
        var outcomes = await S.Modules["system-junk"].CleanAsync(RemovalMode.Recycle, items);
        if (outcomes.Count > 0)
        {
            ResultBar.Title = "Pulizia completata";
            ResultBar.Message = Text.Summary(outcomes, RemovalMode.Recycle);
            ResultBar.IsOpen = true;
        }
        Render();
    }
}
