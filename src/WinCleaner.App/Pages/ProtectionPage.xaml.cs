using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Protection;
using WinCleaner.Modules.Protection.Checks;

namespace WinCleaner.App.Pages;

/// <summary>Heuristic protection checks, each with its reason; nothing is removed automatically.</summary>
public sealed partial class ProtectionPage : Page
{
    private bool _busy;
    private bool _showInfo;

    public ProtectionPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Protezione";
        DescriptionText.Text = "Controlla le difese di Windows, i programmi all'avvio, le estensioni dei browser e le impostazioni di rete, spiegando il motivo di ogni avviso. Per cercare virus usa l'analisi di Microsoft Defender.";
        Toolbar.Children.Add(UI.Button("Analizza", async (_, _) => await ScanAsync(), glyph: ""));
        Toolbar.Children.Add(UI.Button("Analisi rapida con Defender", async (_, _) => await DefenderAsync(), accent: true, glyph: ""));
        Footer.Children.Add(new HyperlinkButton { Content = "Apri Sicurezza di Windows", NavigateUri = new Uri("windowsdefender:") });
        var info = new CheckBox { Content = "Mostra anche le informazioni", IsChecked = false };
        info.Checked += (_, _) => { _showInfo = true; if (AppState.Current.Findings is { } f) Fill(f); };
        info.Unchecked += (_, _) => { _showInfo = false; if (AppState.Current.Findings is { } f) Fill(f); };
        Footer.Children.Add(info);
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
            var findings = await ProtectionActions.ScanAsync();
            Fill(findings);
        }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
        }
    }

    private async Task DeepScanAsync()
    {
        if (_busy) return;
        _busy = true;
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = "Raccolta delle informazioni di sistema in corso…";
        try
        {
            var findings = await ProtectionActions.DeepScanAsync();
            Fill(findings);
        }
        catch (OperationCanceledException) { StatusText.Text = ""; }
        catch (Exception e) { UI.Show(Bar, "Controllo approfondito non riuscito", e.Message, InfoBarSeverity.Error); }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
        }
    }

    private async Task RunAsync(string title, Func<Task<string?>> action)
    {
        try
        {
            var message = await action();
            if (message is not null) UI.Show(Bar, title, message);
            await ScanAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception e) { UI.Show(Bar, title + ": non riuscito", e.Message, InfoBarSeverity.Error); }
    }

    private void Fill(IReadOnlyList<Finding> findings)
    {
        List.Items.Clear();
        int problems = findings.Count(f => f.Severity >= Severity.Warning);
        int fresh = findings.Count(f => f.IsNew && f.Severity >= Severity.Warning);
        StatusText.Text = (problems == 0 ? "Nessun problema da controllare." : $"{problems} avvisi da controllare")
            + (fresh > 0 ? $" · {fresh} nuovi dall'ultimo controllo" : "");
        var visible = findings.Where(f => _showInfo || f.Severity >= Severity.Warning || f.Severity == Severity.Ok).ToList();
        foreach (var category in Categories.Order.Concat(visible.Select(f => f.Category)).Distinct())
        {
            var group = visible.Where(f => f.Category == category).ToList();
            if (group.Count == 0) continue;
            List.Items.Add(UI.Header(category));
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
        if (f.Path is { } path && !path.StartsWith("HKEY_", StringComparison.Ordinal)) actions.Add(UI.Button("Mostra", (_, _) => Shell.Reveal(path)));
        if (f.Path is { } key && key.StartsWith("HKEY_", StringComparison.Ordinal)) actions.Add(UI.Button("Apri nel registro", (_, _) => Shell.OpenRegistryKey(key)));
        if (f.Action == FindingAction.FixSetting && PostureFixes.CanFix(f.Id))
            actions.Add(UI.Button("Correggi", async (_, _) =>
            {
                var done = await Task.Run(() => PostureFixes.Apply(f.Id));
                if (done is not null) UI.Show(Bar, "Fatto", done);
                await ScanAsync();
            }, accent: f.Severity == Severity.Danger));
        if (f.Startup is { Enabled: true } startup)
            actions.Add(UI.Button("Disattiva all'avvio", async (_, _) => await RunAsync("Avvio automatico", async () => { await ProtectionActions.DisableStartupAsync(startup); return $"{startup.Name} non partirà più da solo."; })));
        if (f.Action == FindingAction.RemoveRegistryValue && f.Registry is { } target)
            actions.Add(UI.Button(IsRestore(target) ? "Ripristina valore" : "Elimina voce", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync(IsRestore(target) ? "Ripristinare il valore predefinito?" : "Eliminare la voce del registro?",
                    $"{target.KeyPath}\n[{(target.ValueName.Length == 0 ? "(predefinito)" : target.ValueName)}]\n\nViene salvato prima un file .reg che la ripristina con un doppio clic.", "Procedi", destructive: true)) return;
                await RunAsync("Registro", async () => { var backup = await ProtectionActions.RemoveRegistryValueAsync(target); return $"Fatto. Backup: {backup}"; });
            }, accent: f.Severity == Severity.Danger));
        if (f.Id.StartsWith("defender-exclusion|"))
        {
            var parts = f.Id.Split('|', 3);
            actions.Add(UI.Button("Togli esclusione", async (_, _) => await RunAsync("Defender", async () => { await ProtectionActions.RemoveDefenderExclusionAsync(parts[1], parts[2]); return "Esclusione rimossa."; }), accent: f.Severity == Severity.Danger));
        }
        if (f.Id is "defender-realtime" or "defender-pref-realtime")
            actions.Add(UI.Button("Riattiva", async (_, _) => await RunAsync("Defender", async () => { await ProtectionActions.EnableDefenderRealtimeAsync(); return "Protezione in tempo reale riattivata."; }), accent: true));
        if (f.Id.StartsWith("wmi|"))
            actions.Add(UI.Button("Rimuovi sottoscrizione", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync("Rimuovere la sottoscrizione WMI?", f.Title + "\n\nIl comando non partirà più agli eventi di sistema.", "Rimuovi", destructive: true)) return;
                await RunAsync("WMI", async () => { await ProtectionActions.RemoveWmiSubscriptionAsync(f.Id["wmi|".Length..]); return "Sottoscrizione rimossa."; });
            }, accent: true));
        if (f.ProcessId is { } pid && f.Action == FindingAction.TerminateProcess)
            actions.Add(UI.Button("Termina", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync($"Terminare {f.Title}?", "Il processo verrà chiuso. Se riparte da solo, metti in quarantena il suo file.", "Termina", destructive: true)) return;
                await RunAsync("Processo", async () => { await ProtectionActions.TerminateAsync(pid, f.Path); return "Processo terminato."; });
            }));
        if (f.Path is { } file && !file.StartsWith("HKEY_", StringComparison.Ordinal) && (File.Exists(file) || Directory.Exists(file)) && !Modules.Protection.Suspicion.IsInWindows(file))
        {
            actions.Add(UI.Button("Defender", async (_, _) => await RunAsync("Analisi di Defender", async () => await ProtectionActions.DefenderScanAsync(file))));
            if (f.Severity >= Severity.Warning && f.Category is not (Categories.Defences or Categories.Configuration or Categories.Network or Categories.Devices))
                actions.Add(UI.Button("Quarantena", async (_, _) =>
                {
                    if (!await Dialogs.ConfirmAsync($"Mettere in quarantena {f.Title}?",
                        (f.ProcessId is not null ? "Il processo verrà terminato. " : "") + (f.Startup is { Enabled: true } ? "L'avvio automatico verrà disattivato. " : "")
                        + $"Il file finirà nella quarantena di WinCleaner, senza permessi di esecuzione: potrai ripristinarlo o eliminarlo dalla pagina Quarantena.\n\n{file}", "Metti in quarantena", destructive: true)) return;
                    await RunAsync("Quarantena", async () => await ProtectionActions.QuarantineAsync(f));
                }, accent: f.Severity == Severity.Danger));
        }
        if (f.Publisher is { } publisher && f.Severity < Severity.Danger)
            actions.Add(UI.Button("Fidati di " + Short(publisher), async (_, _) =>
            {
                AppState.Current.Settings.TrustedPublishers.Add(publisher);
                AppState.Current.Settings.Save();
                await ScanAsync();
            }));
        if (f.Severity != Severity.Ok)
            actions.Add(UI.Button("Ignora", async (_, _) =>
            {
                AppState.Current.Settings.IgnoredFindings.Add(f.Id);
                AppState.Current.Settings.Save();
                await ScanAsync();
            }));
        var row = UI.Row(icon, f.IsNew ? $"{f.Title}  · NUOVO" : f.Title, f.Reason + (f.Path is null ? "" : "\n" + f.Path), [.. actions]);
        if (f.Evidence.Length == 0) return row;
        var panel = new StackPanel();
        panel.Children.Add(row);
        var evidence = new TextBlock { Text = string.Join("\n", f.Evidence), FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), FontSize = 12, IsTextSelectionEnabled = true, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(40, 0, 0, 6) };
        panel.Children.Add(new Expander { Header = "Dettagli", Content = evidence, Margin = new Thickness(32, 0, 0, 4), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch });
        return panel;
    }

    private static bool IsRestore(RegistryTargetInfo target) =>
        target.ValueName is "Shell" or "Userinit" or "AppInit_DLLs";

    private static string Short(string publisher) => publisher.Length > 24 ? publisher[..22] + "…" : publisher;

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
