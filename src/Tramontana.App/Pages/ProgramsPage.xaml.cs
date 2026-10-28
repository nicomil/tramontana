using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Tramontana.App.Services;
using Tramontana.Core;
using Tramontana.Modules.Apps;

namespace Tramontana.App.Pages;

public sealed partial class ProgramsPage : Page
{
    private List<InstalledProgram> _all = [];
    private readonly Dictionary<string, long> _sizes = [];
    private bool _busy;

    public ProgramsPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        Loaded += async (_, _) => { if (_all.Count == 0) await LoadAsync(); };
    }

    private static Style Res(string key) => (Style)Application.Current.Resources[key];

    private async Task LoadAsync()
    {
        LoadingRing.IsActive = true;
        _all = await Task.Run(() => InstalledPrograms.All());
        LoadingRing.IsActive = false;
        Fill();
        // Sizes missing from the registry (Store apps, some installers) are measured in the background.
        _ = Task.Run(() =>
        {
            foreach (var p in _all.Where(p => p.Size == 0 && p.InstallLocation is not null).ToList())
            {
                long size = FileWalker.Measure(p.InstallLocation!).Bytes;
                lock (_sizes) _sizes[p.Id] = size;
            }
        }).ContinueWith(_ => DispatcherQueue.TryEnqueue(Fill));
    }

    private long SizeOf(InstalledProgram p)
    {
        lock (_sizes) return p.Size > 0 ? p.Size : _sizes.GetValueOrDefault(p.Id);
    }

    private void Fill()
    {
        string query = Search.Text.Trim();
        IEnumerable<InstalledProgram> list = _all;
        if (query.Length > 0)
            list = list.Where(p => p.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) || (p.Publisher?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false));
        list = KindBox.SelectedIndex switch
        {
            1 => list.Where(p => p.Source == ProgramSource.Desktop),
            2 => list.Where(p => p.Source == ProgramSource.Store),
            _ => list,
        };
        list = SortBox.SelectedIndex switch
        {
            1 => list.OrderByDescending(SizeOf),
            2 => list.OrderByDescending(p => p.InstallDate ?? DateTime.MinValue),
            3 => list.OrderBy(p => p.LastUsedUtc ?? DateTime.MaxValue),
            _ => list.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase),
        };
        var selected = (List.SelectedItem as ListViewItem)?.Tag as InstalledProgram;
        List.Items.Clear();
        foreach (var p in list)
        {
            var item = Row(p);
            List.Items.Add(item);
            if (selected?.Id == p.Id) List.SelectedItem = item;
        }
    }

    private ListViewItem Row(InstalledProgram p)
    {
        var grid = new Grid { ColumnSpacing = 12, Padding = new Thickness(0, 6, 0, 6) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.Children.Add(new FontIcon { Glyph = p.Source == ProgramSource.Store ? "" : "", FontSize = 18 });
        var texts = new StackPanel();
        texts.Children.Add(new TextBlock { Text = p.Name, TextTrimming = TextTrimming.CharacterEllipsis });
        string sub = string.Join(" · ", new[] { p.Publisher, p.Version, p.LastUsedUtc is { } u ? "usato " + Tramontana.Modules.UserFilesWalker.Age(u) : null }.Where(s => !string.IsNullOrEmpty(s)));
        texts.Children.Add(new TextBlock { Text = sub, Style = Res("Caption"), TextTrimming = TextTrimming.CharacterEllipsis, TextWrapping = TextWrapping.NoWrap });
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);
        long size = SizeOf(p);
        var sizeText = new TextBlock { Text = size > 0 ? Format.Bytes(size) : "", VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(sizeText, 2);
        grid.Children.Add(sizeText);
        return new ListViewItem { Content = grid, Tag = p };
    }

    private void Search_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => Fill();
    private void Filter_Changed(object sender, SelectionChangedEventArgs e) { if (IsLoaded) Fill(); }
    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private void List_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails((List.SelectedItem as ListViewItem)?.Tag as InstalledProgram);

    private void ShowDetails(InstalledProgram? p)
    {
        Details.Children.Clear();
        if (p is null)
        {
            Details.Children.Add(new TextBlock { Text = "Scegli un programma dall'elenco.", Style = Res("Caption") });
            return;
        }
        Details.Children.Add(new TextBlock { Text = p.Name, Style = Res("SubtitleTextBlockStyle"), TextWrapping = TextWrapping.Wrap });
        void Field(string label, string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock { Text = label, Style = Res("Caption") });
            panel.Children.Add(new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            Details.Children.Add(panel);
        }
        Field("Editore", p.Publisher);
        Field("Versione", p.Version);
        long size = SizeOf(p);
        Field("Dimensione", size > 0 ? Format.Bytes(size) : null);
        Field("Installato il", p.InstallDate?.ToString("d MMMM yyyy"));
        Field("Ultimo uso", p.LastUsedUtc is { } u ? $"{u.ToLocalTime():d MMMM yyyy} ({Tramontana.Modules.UserFilesWalker.Age(u)})" : "Non registrato");
        Field("Tipo", p.Source == ProgramSource.Store ? "App di Microsoft Store" : p.PerUser ? "Programma per questo utente" : "Programma per tutti gli utenti (chiede l'amministratore)");
        Field("Cartella", p.InstallLocation);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
        var uninstall = new Button { Content = "Disinstalla", Style = Res("AccentButtonStyle"), IsEnabled = !_busy && !p.NoRemove };
        uninstall.Click += async (_, _) => await UninstallAsync(p);
        buttons.Children.Add(uninstall);
        var leftovers = new Button { Content = "File collegati", IsEnabled = !_busy };
        ToolTipService.SetToolTip(leftovers, "Dati, impostazioni e collegamenti del programma");
        leftovers.Click += async (_, _) => await ReviewLeftoversAsync(p, uninstalled: false);
        if (p.Source == ProgramSource.Desktop) buttons.Children.Add(leftovers);
        if (p.InstallLocation is { } folder)
        {
            var open = new Button { Content = new FontIcon { Glyph = "", FontSize = 14 } };
            ToolTipService.SetToolTip(open, "Apri la cartella");
            open.Click += (_, _) => Shell.Open(folder);
            buttons.Children.Add(open);
        }
        Details.Children.Add(buttons);
        if (p.NoRemove) Details.Children.Add(new TextBlock { Text = "Il programma non si può disinstallare da qui.", Style = Res("Caption") });
    }

    /// <summary>
    /// Closes the program, runs its uninstaller, then looks for leftovers.
    /// The list is locked while this runs, so a refresh cannot swap the
    /// program the leftovers are matched against.
    /// </summary>
    private async Task UninstallAsync(InstalledProgram p)
    {
        if (_busy) return;
        bool running = p.InstallLocation is { } l && InstalledPrograms.ProcessesIn(l).Count > 0;
        string message = $"Verrà avviato il programma di disinstallazione di {p.Name}." +
                         (running ? "\n\nIl programma è aperto: verrà chiuso (salva prima il tuo lavoro)." : "") +
                         "\n\nAlla fine potrai scegliere quali avanzi togliere.";
        if (!await Dialogs.ConfirmAsync($"Disinstallare {p.Name}?", message, "Disinstalla", destructive: true)) return;
        _busy = true;
        List.IsEnabled = false;
        ShowDetails(p);
        var status = new InfoBar { IsOpen = true, Severity = InfoBarSeverity.Informational, Title = "Disinstallazione in corso", Message = "Segui le istruzioni del programma di disinstallazione.", IsClosable = false };
        Details.Children.Insert(1, status);
        try
        {
            await ProgramUninstaller.CloseRunningAsync(p, TimeSpan.FromSeconds(6), CancellationToken.None);
            var result = await ProgramUninstaller.RunAsync(p, CancellationToken.None);
            OperationLog.Standard.Write($"uninstall\t{result.Status}\t{p.Name}");
            status.IsOpen = false;
            if (result.Status == UninstallStatus.Cancelled) return;
            if (result.Status == UninstallStatus.Failed)
            {
                await Dialogs.InfoAsync("Disinstallazione non riuscita", result.Message ?? "");
                if (result.Message?.Contains("non c'è più") == true) await ReviewLeftoversAsync(p, uninstalled: true);
                return;
            }
            if (result.Status == UninstallStatus.StillInstalled && p.Source == ProgramSource.Desktop)
            {
                await Dialogs.InfoAsync("Programma ancora installato", "Il programma di disinstallazione è terminato ma il programma risulta ancora installato. Gli avanzi non vengono cercati.");
                return;
            }
            if (p.Source == ProgramSource.Desktop) await ReviewLeftoversAsync(p, uninstalled: true);
        }
        finally
        {
            _busy = false;
            List.IsEnabled = true;
            await LoadAsync();
        }
    }

    private async Task ReviewLeftoversAsync(InstalledProgram p, bool uninstalled)
    {
        var installed = await Task.Run(() => InstalledPrograms.All());
        var report = await Task.Run(() => LeftoverFinder.Find(p, installed, uninstalled));
        var items = report.AllItems.ToList();
        if (items.Count == 0)
        {
            await Dialogs.InfoAsync(uninstalled ? "Nessun avanzo" : "Nessun file collegato", uninstalled ? $"{p.Name} non ha lasciato file o impostazioni." : "Non ci sono dati o impostazioni del programma da mostrare.");
            return;
        }
        var checks = new List<(CheckBox Box, ScanItem Item)>();
        var panel = new StackPanel { Spacing = 4 };
        panel.Children.Add(new TextBlock
        {
            Text = uninstalled
                ? "Sono preselezionati solo la cartella del programma rimasta, la sua voce in App installate e i collegamenti che non funzionano più. Dati e impostazioni possono contenere il tuo lavoro."
                : "Il programma è ancora installato: togliere dati e impostazioni equivale a un ripristino. Nulla è preselezionato.",
            TextWrapping = TextWrapping.Wrap, Style = Res("Caption"), Margin = new Thickness(0, 0, 0, 8),
        });
        foreach (var category in report.Categories)
        {
            panel.Children.Add(new TextBlock { Text = category.Title, Style = Res("BodyStrongTextBlockStyle"), Margin = new Thickness(0, 6, 0, 0) });
            foreach (var item in category.Items)
            {
                var box = new CheckBox { IsChecked = uninstalled && item.AutoSelect };
                var content = new StackPanel();
                content.Children.Add(new TextBlock { Text = item.Kind == ItemKind.File ? item.Path : item.Label ?? item.Path, TextWrapping = TextWrapping.Wrap });
                content.Children.Add(new TextBlock { Text = $"{item.Detail}{(item.Size > 0 ? " · " + Format.Bytes(item.Size) : "")}{(item.NeedsAdmin ? " · amministratore" : "")}", Style = Res("Caption") });
                box.Content = content;
                checks.Add((box, item));
                panel.Children.Add(box);
            }
        }
        var dialog = new ContentDialog
        {
            Title = uninstalled ? $"Avanzi di {p.Name}" : $"File collegati a {p.Name}",
            Content = new ScrollViewer { Content = panel, MaxHeight = 460 },
            PrimaryButtonText = "Sposta nel Cestino",
            CloseButtonText = "Lascia tutto",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await Dialogs.ShowAsync(dialog) != ContentDialogResult.Primary) return;
        var chosen = checks.Where(c => c.Box.IsChecked == true).Select(c => c.Item).ToList();
        if (chosen.Count == 0) return;

        var outcomes = new List<RemovalOutcome>();
        var userFiles = chosen.Where(i => !i.NeedsAdmin && i.Kind == ItemKind.File).Select(i => i.Path).ToList();
        var userRegistry = chosen.Where(i => !i.NeedsAdmin && i.Kind != ItemKind.File).Select(i => new RegistryTarget(i.Path)).ToList();
        outcomes.AddRange(await Task.Run(() => new SafeRemover(LeftoverFinder.AllowedRoots(p), RemovalMode.Recycle, OperationLog.Standard).Remove(userFiles)));
        outcomes.AddRange(await Task.Run(() => new RegistryCleaner(RemovalMode.Delete, OperationLog.Standard).Remove(userRegistry)));
        var admin = chosen.Where(i => i.NeedsAdmin).ToList();
        if (admin.Count > 0)
        {
            try { outcomes.AddRange(await AppState.Current.CleanAdminItemsAsync(admin, RemovalMode.Recycle)); }
            catch (OperationCanceledException) { }
            catch (Exception e) { await Dialogs.InfoAsync("Elementi di sistema non rimossi", e.Message); }
        }
        var failed = outcomes.Where(o => !o.Succeeded).ToList();
        await Dialogs.InfoAsync("Avanzi rimossi", Text.Summary(outcomes, RemovalMode.Recycle) +
            (failed.Count > 0 ? "\n\n" + string.Join("\n", failed.Take(5).Select(f => $"{f.Path}: {Text.Error(f.Error)}")) : ""));
    }
}
