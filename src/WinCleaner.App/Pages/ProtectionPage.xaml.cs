using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Protection;

namespace WinCleaner.App.Pages;

/// <summary>Heuristic protection checks, each with its reason; nothing is removed automatically.</summary>
public sealed partial class ProtectionPage : Page
{
    private bool _busy;

    public ProtectionPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Protezione";
        DescriptionText.Text = "Controlla le difese di Windows, i programmi all'avvio, le estensioni dei browser e le impostazioni di rete, spiegando il motivo di ogni avviso. Per cercare virus usa l'analisi di Microsoft Defender.";
        Toolbar.Children.Add(UI.Button("Analizza", async (_, _) => await ScanAsync(), glyph: ""));
        Toolbar.Children.Add(UI.Button("Analisi rapida con Defender", async (_, _) => await DefenderAsync(), accent: true, glyph: ""));
        Footer.Children.Add(new HyperlinkButton { Content = "Apri Sicurezza di Windows", NavigateUri = new Uri("windowsdefender:") });
        Footer.Children.Add(UI.Button("Mostra anche gli avvisi ignorati", async (_, _) =>
        {
            AppState.Current.Settings.IgnoredFindings.Clear();
            AppState.Current.Settings.Save();
            await ScanAsync();
        }));
        Loaded += async (_, _) => { if (AppState.Current.Findings is null) await ScanAsync(); else Fill(AppState.Current.Findings); };
    }

    private async Task ScanAsync()
    {
        if (_busy) return;
        _busy = true;
        Progress.Visibility = Visibility.Visible;
        try
        {
            var findings = await Task.Run(() => ProtectionScanner.Scan(AppState.Current.Settings.IgnoredFindings));
            AppState.Current.Findings = findings;
            Fill(findings);
        }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
        }
    }

    private void Fill(IReadOnlyList<Finding> findings)
    {
        List.Items.Clear();
        int problems = findings.Count(f => f.Severity >= Severity.Warning);
        StatusText.Text = problems == 0 ? "Nessun problema da controllare." : $"{problems} avvisi da controllare";
        foreach (var group in findings.GroupBy(f => f.Category))
        {
            List.Items.Add(UI.Header(group.Key));
            foreach (var f in group.OrderByDescending(f => f.Severity)) List.Items.Add(Row(f));
        }
    }

    private FrameworkElement Row(Finding f)
    {
        var (glyph, brush) = f.Severity switch
        {
            Severity.Danger => ("", "SystemFillColorCriticalBrush"),
            Severity.Warning => ("", "SystemFillColorCautionBrush"),
            Severity.Info => ("", "SystemFillColorAttentionBrush"),
            _ => ("", "SystemFillColorSuccessBrush"),
        };
        var icon = new FontIcon { Glyph = glyph, FontSize = 18, Foreground = UI.Brush(brush) };
        var actions = new List<FrameworkElement>();
        if (f.SettingsLink is { } link) actions.Add(UI.Button("Apri", (_, _) => Shell.Open(link)));
        if (f.Path is { } path) actions.Add(UI.Button("Mostra", (_, _) => Shell.Reveal(path)));
        if (f.Startup is { Enabled: true } startup && startup.Kind is StartupKind.RunKey or StartupKind.StartupFolder && !startup.NeedsAdmin)
            actions.Add(UI.Button("Disattiva all'avvio", async (_, _) =>
            {
                StartupManager.SetApproved(startup, false);
                AppState.Current.Startup = null;
                await ScanAsync();
            }));
        if (f.Severity != Severity.Ok)
            actions.Add(UI.Button("Ignora", async (_, _) =>
            {
                AppState.Current.Settings.IgnoredFindings.Add(f.Id);
                AppState.Current.Settings.Save();
                await ScanAsync();
            }));
        var row = UI.Row(icon, f.Title, f.Reason, [.. actions]);
        return row;
    }

    private async Task DefenderAsync()
    {
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = "Analisi rapida di Microsoft Defender in corso: può richiedere qualche minuto…";
        try
        {
            var result = await ProtectionScanner.DefenderQuickScanAsync(CancellationToken.None);
            UI.Show(Bar, "Microsoft Defender", result, result.Contains("trovato") ? InfoBarSeverity.Error : InfoBarSeverity.Success);
            StatusText.Text = "";
        }
        finally { Progress.Visibility = Visibility.Collapsed; }
    }
}
