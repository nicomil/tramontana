using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Performance;

namespace WinCleaner.App.Pages;

/// <summary>
/// Startup programs. Turning one off works like Task Manager (the entry
/// stays and can be turned on again); removing deletes it, after a .reg
/// backup or into the Recycle Bin.
/// </summary>
public sealed partial class StartupPage : Page
{
    private bool _busy;

    public StartupPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Avvio automatico";
        DescriptionText.Text = "Programmi che partono con Windows, attività pianificate e servizi non di Microsoft. Disattivare è sempre reversibile; le attività di Windows non vengono mostrate.";
        Toolbar.Children.Add(UI.Button("Aggiorna", async (_, _) => await LoadAsync(), glyph: ""));
        Toolbar.Children.Add(UI.Button("Gestione attività", (_, _) => Shell.Open("taskmgr.exe"), glyph: ""));
        Loaded += async (_, _) => { if (AppState.Current.Startup is null) await LoadAsync(); else Fill(AppState.Current.Startup); };
    }

    private async Task LoadAsync()
    {
        Progress.Visibility = Visibility.Visible;
        var items = await Task.Run(() => StartupManager.List());
        AppState.Current.Startup = items;
        Fill(items);
        Progress.Visibility = Visibility.Collapsed;
        StatusText.Text = $"{items.Count(i => i.Enabled)} attivi su {items.Count}";
    }

    private void Fill(IReadOnlyList<StartupItem> items)
    {
        List.Items.Clear();
        var running = StartupManager.RunningExecutables();
        var groups = new (StartupKind Kind, string Title)[]
        {
            (StartupKind.RunKey, "Programmi all'avvio"), (StartupKind.StartupFolder, "Cartella Esecuzione automatica"),
            (StartupKind.ScheduledTask, "Attività pianificate"), (StartupKind.Service, "Servizi"),
        };
        foreach (var (kind, title) in groups)
        {
            var list = items.Where(i => i.Kind == kind).OrderBy(i => i.Name).ToList();
            if (list.Count == 0) continue;
            List.Items.Add(UI.Header(title));
            foreach (var item in list) List.Items.Add(Row(item, running));
        }
    }

    private FrameworkElement Row(StartupItem item, HashSet<string> running)
    {
        var toggle = new ToggleSwitch { IsOn = item.Enabled, OnContent = "", OffContent = "", MinWidth = 0, Width = 60 };
        toggle.Toggled += async (_, _) => await SetEnabledAsync(item, toggle);
        string signature = item.Signature switch
        {
            { Status: SignatureStatus.Signed, Publisher: { } p } => p,
            { Status: SignatureStatus.Unsigned } => "senza firma digitale",
            { Status: SignatureStatus.Invalid } => "firma non valida",
            _ => "",
        };
        var parts = new List<string> { item.Location };
        if (signature.Length > 0) parts.Add(signature);
        if (item.Kind == StartupKind.Service) parts.Add(item.StartType == 4 ? "disattivato" : item.DelayedStart ? "automatico ritardato" : item.Enabled ? "automatico" : "manuale");
        if (item.Executable is { } exe && running.Contains(exe)) parts.Add("in esecuzione");
        if (item.NeedsAdmin) parts.Add("amministratore");
        var trailing = new List<FrameworkElement>();
        if (item.IsBroken)
            trailing.Add(new Border { CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 1, 6, 1), Background = UI.Brush("SystemFillColorCautionBackgroundBrush"), Child = new TextBlock { Text = "programma mancante", Style = UI.Style("CaptionTextBlockStyle") } });
        if (item.Executable is { } path)
        {
            var reveal = new Button { Content = new FontIcon { Glyph = "", FontSize = 14 } };
            ToolTipService.SetToolTip(reveal, item.Command);
            reveal.Click += (_, _) => Shell.Reveal(path);
            trailing.Add(reveal);
        }
        if (item.Kind != StartupKind.Service)
        {
            var remove = new Button { Content = new FontIcon { Glyph = "", FontSize = 14 } };
            ToolTipService.SetToolTip(remove, "Rimuovi");
            remove.Click += async (_, _) => await RemoveAsync(item);
            trailing.Add(remove);
        }
        return UI.Row(toggle, item.Name, string.Join(" · ", parts), [.. trailing]);
    }

    private async Task SetEnabledAsync(StartupItem item, ToggleSwitch toggle)
    {
        if (_busy) return;
        bool enabled = toggle.IsOn;
        _busy = true;
        try
        {
            switch (item.Kind)
            {
                case StartupKind.RunKey or StartupKind.StartupFolder when !item.NeedsAdmin:
                    StartupManager.SetApproved(item, enabled);
                    break;
                case StartupKind.RunKey or StartupKind.StartupFolder:
                    await Helper(new HelperRequest { Operation = HelperOperation.SetStartupApproved, Key = item.ApprovedKey, Name = item.ValueName, Enabled = enabled });
                    break;
                case StartupKind.ScheduledTask:
                    try { StartupManager.SetTaskEnabled(item.TaskPath!, enabled); }
                    catch (UnauthorizedAccessException) { await Helper(new HelperRequest { Operation = HelperOperation.SetTaskEnabled, Name = item.TaskPath, Enabled = enabled }); }
                    break;
                case StartupKind.Service:
                    if (!enabled && !await Dialogs.ConfirmAsync("Avvio manuale?", $"Il servizio «{item.Name}» non partirà più da solo con Windows: si avvierà solo quando un programma lo chiede. Alcune funzioni del programma che lo installa potrebbero non funzionare.", "Imposta manuale"))
                    {
                        Revert();
                        return;
                    }
                    await Helper(new HelperRequest { Operation = HelperOperation.SetServiceStart, Name = item.ServiceName, Number = enabled ? 2 : 3 });
                    break;
            }
            StatusText.Text = $"{item.Name}: {(enabled ? "attivato" : "disattivato")}";
        }
        catch (Exception e)
        {
            Revert();
            UI.Show(Bar, "Modifica non riuscita", e is OperationCanceledException ? "Richiesta di amministratore annullata" : e.Message, InfoBarSeverity.Warning);
        }
        finally { _busy = false; }

        void Revert()
        {
            _busy = true;
            toggle.IsOn = !enabled;
            _busy = false;
        }
    }

    private static async Task Helper(HelperRequest request)
    {
        var helper = await AppState.Current.EnsureHelperAsync();
        var response = await helper.SendAsync(request, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
    }

    private async Task RemoveAsync(StartupItem item)
    {
        string how = item.Kind switch
        {
            StartupKind.RunKey => "La voce viene salvata in un file .reg prima di toglierla.",
            StartupKind.StartupFolder => "Il collegamento va nel Cestino.",
            _ => "L'attività viene eliminata dall'Utilità di pianificazione.",
        };
        if (!await Dialogs.ConfirmAsync($"Rimuovere «{item.Name}»?", $"{how} Se vuoi solo che non parta, usa l'interruttore: è reversibile.", "Rimuovi", destructive: true)) return;
        try
        {
            switch (item.Kind)
            {
                case StartupKind.RunKey or StartupKind.StartupFolder when !item.NeedsAdmin:
                    var outcome = await Task.Run(() => StartupManager.Remove(item));
                    if (!outcome.Succeeded) throw new InvalidOperationException(Text.Error(outcome.Error));
                    break;
                case StartupKind.RunKey:
                    await Helper(new HelperRequest { Operation = HelperOperation.RemoveRegistry, Registry = [new RegistryTarget(item.RegistryKey!, item.ValueName)] });
                    break;
                case StartupKind.StartupFolder:
                    await Helper(new HelperRequest { Operation = HelperOperation.Remove, Paths = [item.FilePath!], Mode = RemovalMode.Recycle });
                    break;
                case StartupKind.ScheduledTask:
                    try { StartupManager.DeleteTask(item.TaskPath!); }
                    catch (UnauthorizedAccessException) { await Helper(new HelperRequest { Operation = HelperOperation.DeleteTask, Name = item.TaskPath }); }
                    break;
            }
            await LoadAsync();
        }
        catch (Exception e)
        {
            UI.Show(Bar, "Rimozione non riuscita", e is OperationCanceledException ? "Richiesta di amministratore annullata" : e.Message, InfoBarSeverity.Warning);
        }
    }
}
