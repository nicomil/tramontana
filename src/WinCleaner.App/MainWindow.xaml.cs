using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using WinCleaner.App.Pages;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Performance;

namespace WinCleaner.App;

public sealed partial class MainWindow : Window
{
    private sealed record Entry(string Tag, string Title, string Glyph, Type Page, string? Parameter = null);

    private static readonly (string Section, Entry[] Entries)[] Menu =
    [
        ("", [new("health", "Controllo integrità", "", typeof(HealthPage))]),
        ("Pulizia", [
            new("system-junk", "Pulizia sistema", "", typeof(ModulePage), "system-junk"),
            new("recycle-bin", "Cestini", "", typeof(ModulePage), "recycle-bin"),
            new("registry", "Registro", "", typeof(ModulePage), "registry"),
        ]),
        ("File", [
            new("space-lens", "Analisi disco", "", typeof(SpaceLensPage)),
            new("large-old-files", "File grandi e vecchi", "", typeof(ModulePage), "large-old-files"),
            new("duplicates", "Duplicati", "", typeof(ModulePage), "duplicates"),
            new("similar-images", "Immagini simili", "", typeof(ModulePage), "similar-images"),
            new("installers", "Installer", "", typeof(ModulePage), "installers"),
        ]),
        ("Programmi", [
            new("programs", "Disinstallazione", "", typeof(ProgramsPage)),
            new("updates", "Aggiornamenti", "", typeof(UpdatesPage)),
            new("orphans", "Avanzi di programmi rimossi", "", typeof(ModulePage), "orphans"),
        ]),
        ("Protezione", [
            new("privacy", "Privacy", "", typeof(PrivacyPage)),
            new("protection", "Protezione", "", typeof(ProtectionPage)),
        ]),
        ("Prestazioni", [
            new("startup", "Avvio automatico", "", typeof(StartupPage)),
            new("maintenance", "Manutenzione", "", typeof(MaintenancePage)),
        ]),
    ];

    private readonly Dictionary<string, TextBlock> _badges = [];
    private readonly Dictionary<string, NavigationViewItem> _items = [];
    private TrayIcon? _tray;
    private readonly SystemMonitor _monitor = new();
    private DispatcherTimer? _trayTimer;
    private readonly WinCleaner.Modules.Protection.Checks.BusyProcessWatcher _busyWatcher = new();
    private int _lastBusyPid;
    private bool _quitting;

    public MainWindow()
    {
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBar);
        SystemBackdrop = new MicaBackdrop();
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico"));
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1240, 820));
        if (AppWindow.Presenter is OverlappedPresenter presenter) { presenter.PreferredMinimumWidth = 900; presenter.PreferredMinimumHeight = 600; }

        BuildMenu();
        AppState.Current.BadgesChanged += () => DispatcherQueue.TryEnqueue(UpdateBadges);
        AppState.Current.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AppState.IsHelperRunning))
                DispatcherQueue.TryEnqueue(() => AdminBadge.Visibility = AppState.Current.IsHelperRunning ? Visibility.Visible : Visibility.Collapsed);
        };
        AppWindow.Closing += OnClosing;
        Activated += OnFirstActivated;
        if (AppState.Current.Settings.TrayIcon) EnableTray(true);
    }

    private void OnFirstActivated(object sender, WindowActivatedEventArgs args)
    {
        Activated -= OnFirstActivated;
        Navigate("health");
        // Dialogs need the content in the visual tree (its XamlRoot), which comes with Loaded.
        if (Content is FrameworkElement root)
        {
            if (root.XamlRoot is not null) ShowWelcomeIfNeeded();
            else root.Loaded += (_, _) => ShowWelcomeIfNeeded();
        }
    }

    private void ShowWelcomeIfNeeded()
    {
        if (!AppState.Current.Settings.WelcomeShown) _ = ShowWelcomeAsync();
    }

    private void BuildMenu()
    {
        foreach (var (section, entries) in Menu)
        {
            if (section.Length > 0) Nav.MenuItems.Add(new NavigationViewItemHeader { Content = section });
            foreach (var entry in entries)
            {
                var badge = new TextBlock
                {
                    Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
                    Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(8, 0, 4, 0),
                };
                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                grid.Children.Add(new TextBlock { Text = entry.Title, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
                Grid.SetColumn(badge, 1);
                grid.Children.Add(badge);
                var item = new NavigationViewItem
                {
                    Content = grid,
                    Tag = entry.Tag,
                    Icon = new FontIcon { Glyph = entry.Glyph },
                };
                ToolTipService.SetToolTip(item, entry.Title);
                Nav.MenuItems.Add(item);
                _badges[entry.Tag] = badge;
                _items[entry.Tag] = item;
            }
        }
    }

    private void UpdateBadges()
    {
        foreach (var (tag, state) in AppState.Current.Modules)
            if (_badges.TryGetValue(tag, out var badge)) badge.Text = state.Badge ?? "";
        var state2 = AppState.Current;
        if (state2.Updates is { } updates) _badges["updates"].Text = updates.Count > 0 ? updates.Count.ToString() : "";
        if (state2.Findings is { } findings)
        {
            int problems = findings.Count(f => f.Severity >= WinCleaner.Modules.Protection.Severity.Warning);
            _badges["protection"].Text = problems > 0 ? problems.ToString() : "";
        }
        if (state2.Startup is { } startup) _badges["startup"].Text = startup.Count(s => s.Enabled).ToString();
    }

    /// <summary>Opens every page in turn, logs the outcome and quits: the end-to-end check run on the build machine.</summary>
    public async Task SmokeAsync()
    {
        var failures = new List<string>();
        var tags = Menu.SelectMany(m => m.Entries).Select(e => e.Tag).ToList();
        foreach (var tag in tags)
        {
            try
            {
                Navigate(tag);
                await Task.Delay(TimeSpan.FromSeconds(tag is "protection" or "health" ? 25 : 4));
                if (ContentFrame.Content is null) failures.Add(tag + ": nessuna pagina");
            }
            catch (Exception e) { failures.Add($"{tag}: {e.Message}"); }
        }
        try { Nav.SelectedItem = Nav.SettingsItem; await Task.Delay(2000); }
        catch (Exception e) { failures.Add("settings: " + e.Message); }
        WinCleaner.Core.OperationLog.Standard.Write(failures.Count == 0 ? $"smoke\tok\t{tags.Count + 1} pagine" : "smoke\tFAIL\t" + string.Join(" | ", failures));
        Application.Current.Exit();
    }

    public void Navigate(string tag)
    {
        if (_items.TryGetValue(tag, out var item)) Nav.SelectedItem = item;
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            ContentFrame.Navigate(typeof(SettingsPage));
            return;
        }
        if (args.SelectedItem is not NavigationViewItem { Tag: string tag }) return;
        var entry = Menu.SelectMany(m => m.Entries).First(e => e.Tag == tag);
        ContentFrame.Navigate(entry.Page, entry.Parameter);
    }

    private async Task ShowWelcomeAsync()
    {
        var panel = new StackPanel { Spacing = 14, MaxWidth = 460 };
        void Point(string glyph, string title, string text)
        {
            var row = new Grid { ColumnSpacing = 12 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(32) });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.Children.Add(new FontIcon { Glyph = glyph, FontSize = 22, Foreground = (Brush)Application.Current.Resources["AccentTextFillColorPrimaryBrush"], VerticalAlignment = VerticalAlignment.Top });
            var texts = new StackPanel();
            texts.Children.Add(new TextBlock { Text = title, Style = (Style)Application.Current.Resources["BodyStrongTextBlockStyle"] });
            texts.Children.Add(new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"] });
            Grid.SetColumn(texts, 1);
            row.Children.Add(texts);
            panel.Children.Add(row);
        }
        Point("", "Controllo integrità", "Un clic per controllare pulizia, protezione, aggiornamenti e programmi all'avvio.");
        Point("", "Niente sparisce per sbaglio", "Di default i file vanno nel Cestino e c'è la modalità Prova. Ogni operazione finisce nel registro delle operazioni, e le voci del registro di sistema vengono salvate prima di toglierle.");
        Point("", "Funzioni di sistema", "Per le cartelle di Windows serve l'amministratore: Windows lo chiede una volta sola per sessione, e solo quando servono.");
        var dialog = new ContentDialog { Title = "Benvenuto in WinCleaner", Content = panel, PrimaryButtonText = "Inizia", DefaultButton = ContentDialogButton.Primary };
        await Dialogs.ShowAsync(dialog);
        AppState.Current.Settings.WelcomeShown = true;
        AppState.Current.Settings.Save();
    }

    public void EnableTray(bool enabled)
    {
        if (enabled && _tray is null)
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            _tray = new TrayIcon(hwnd, Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico"), ShowFromTray,
            [
                ("Apri WinCleaner", ShowFromTray),
                ("Controllo integrità", () => { ShowFromTray(); Navigate("health"); }),
                ("Libera memoria", () => _ = FreeMemoryAsync()),
                ("-", () => { }),
                ("Esci", Quit),
            ]);
            _monitor.Next();
            _trayTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _trayTimer.Tick += async (_, _) =>
            {
                var s = _monitor.Next();
                // A non-Microsoft process saturating a core for a minute (20 samples of 3 s) is worth a word.
                var busy = await Task.Run(() => _busyWatcher.Check(20));
                string warning = busy is null ? "" : $"\n⚠ {busy.Name} usa il {busy.Cpu:P0} della CPU da più di un minuto";
                if (busy is not null && _lastBusyPid != busy.Pid)
                {
                    _lastBusyPid = busy.Pid;
                    Notifications.Show("WinCleaner", $"{busy.Name} usa la CPU al {busy.Cpu:P0} da più di un minuto. Apri Attività per vedere cos'è.");
                }
                _tray?.SetTooltip($"WinCleaner\nCPU {s.CpuUsage:P0} · Memoria {s.MemoryUsage:P0}\nDisco C: {Format.Bytes(s.DiskFree)} liberi" +
                                  (s.BatteryLevel is { } b ? $"\nBatteria {b:P0}{(s.IsCharging ? " in carica" : "")}" : "") + warning);
            };
            _trayTimer.Start();
        }
        else if (!enabled && _tray is not null)
        {
            _trayTimer?.Stop();
            _tray.Dispose();
            _tray = null;
        }
    }

    private async Task FreeMemoryAsync()
    {
        try
        {
            string result;
            if (AppState.Current.IsHelperRunning)
            {
                var r = await AppState.Current.Helper!.SendAsync(new WinCleaner.Modules.Helper.HelperRequest
                    { Operation = WinCleaner.Modules.Helper.HelperOperation.Maintenance, Task = WinCleaner.Modules.Helper.MaintenanceKind.FreeMemory }, CancellationToken.None);
                result = r.Text ?? r.Error ?? "";
            }
            else result = await Task.Run(Maintenance.FreeMemory);
            _tray?.SetTooltip("WinCleaner\n" + result);
        }
        catch (Exception) { }
    }

    private void ShowFromTray()
    {
        AppWindow.Show();
        if (AppWindow.Presenter is OverlappedPresenter p && p.State == OverlappedPresenterState.Minimized) p.Restore();
        Activate();
    }

    private void OnClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_quitting && _tray is not null && AppState.Current.Settings.CloseToTray)
        {
            args.Cancel = true;
            sender.Hide();
            return;
        }
        _tray?.Dispose();
        _tray = null;
        _ = AppState.Current.ShutdownAsync();
    }

    public void Quit()
    {
        _quitting = true;
        Close();
    }
}
