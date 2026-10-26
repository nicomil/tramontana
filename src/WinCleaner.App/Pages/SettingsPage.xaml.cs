using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules;

namespace WinCleaner.App.Pages;

public sealed partial class SettingsPage : Page
{
    private static Settings S => AppState.Current.Settings;

    public SettingsPage()
    {
        InitializeComponent();
        Section("Pulizia");
        var mode = new ComboBox { Width = 260 };
        foreach (var m in new[] { RemovalMode.Recycle, RemovalMode.DryRun, RemovalMode.Delete }) mode.Items.Add(new ComboBoxItem { Content = Text.Mode(m), Tag = m });
        mode.SelectedIndex = S.DefaultMode switch { RemovalMode.DryRun => 1, RemovalMode.Delete => 2, _ => 0 };
        mode.SelectionChanged += (_, _) => { S.DefaultMode = (RemovalMode)((ComboBoxItem)mode.SelectedItem).Tag; S.Save(); };
        Setting("Modalità predefinita", "Cosa succede ai file quando pulisci. Il Cestino permette di ripristinarli.", mode);

        var large = new NumberBox { Value = S.LargeFileMegabytes, Minimum = 10, Maximum = 5000, SmallChange = 10, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact, Width = 140 };
        large.ValueChanged += (_, _) =>
        {
            if (double.IsNaN(large.Value)) return;
            S.LargeFileMegabytes = (int)large.Value;
            S.Save();
            if (AppState.Current.Modules["large-old-files"].Module is LargeOldFilesModule m) m.MinimumSize = S.LargeFileMegabytes * 1_000_000L;
        };
        Setting("File grandi da (MB)", "Soglia per «File grandi e vecchi».", large);

        Section("Automatico");
        var schedule = new ComboBox { Width = 200 };
        foreach (var (tag, text) in new[] { ("never", "Mai"), ("daily", "Ogni giorno"), ("weekly", "Ogni settimana") }) schedule.Items.Add(new ComboBoxItem { Content = text, Tag = tag });
        schedule.SelectedIndex = S.Schedule switch { "daily" => 1, "weekly" => 2, _ => 0 };
        schedule.SelectionChanged += (_, _) =>
        {
            S.Schedule = (string)((ComboBoxItem)schedule.SelectedItem).Tag;
            S.Save();
            try { Scheduler.Apply(S.Schedule); }
            catch (Exception e) { _ = Dialogs.InfoAsync("Pianificazione non riuscita", e.Message); }
        };
        Setting("Analisi pianificata", "Cerca i file inutili e manda una notifica se c'è più di 500 MB da liberare. Non rimuove nulla da sola.", schedule);

        Toggle("Icona nell'area di notifica", "Mostra CPU, memoria e disco e offre le azioni rapide.", S.TrayIcon, v => { S.TrayIcon = v; App.Window?.EnableTray(v); });
        Toggle("Chiudendo la finestra resta nell'area di notifica", "Altrimenti chiudere la finestra esce dall'app.", S.CloseToTray, v => S.CloseToTray = v);
        Toggle("Avvia con Windows", "Parte nell'area di notifica, senza aprire la finestra.", S.StartWithWindows, v => { S.StartWithWindows = v; StartWithWindows.Apply(v); });

        Section("Sicurezza e registri");
        Action("Registro delle operazioni", "Ogni file rimosso, spostato o saltato, con data ed esito.", "Apri", () => Shell.Reveal(OperationLog.Standard.FilePath));
        Action("Backup del registro di sistema", "File .reg salvati prima di ogni modifica: un doppio clic ripristina le voci.", "Apri cartella", () =>
        {
            var folder = Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Backups");
            Directory.CreateDirectory(folder);
            Shell.Open(folder);
        });
        Action("Funzioni di sistema", AppState.Current.IsHelperRunning ? "Attive per questa sessione." : "Si attivano alla prima operazione che le richiede (una richiesta di amministratore per sessione).", "Attiva ora", async () =>
        {
            try { await AppState.Current.EnsureHelperAsync(); }
            catch (OperationCanceledException) { }
            catch (Exception e) { await Dialogs.InfoAsync("Non disponibili", e.Message); }
        });

        Section("Informazioni");
        Panel.Children.Add(new TextBlock { Text = $"WinCleaner {typeof(App).Assembly.GetName().Version?.ToString(3)} · uso personale", Style = UI.Style("Caption") });
    }

    private void Section(string title) =>
        Panel.Children.Add(new TextBlock { Text = title, Style = UI.Style("BodyStrongTextBlockStyle"), Margin = new Thickness(0, 16, 0, 4) });

    private void Setting(string title, string description, FrameworkElement control)
    {
        var grid = UI.Row(null, title, description, control);
        Panel.Children.Add(new Border { Style = UI.Style("Card"), Child = grid, Padding = new Thickness(12, 8, 12, 8) });
    }

    private void Toggle(string title, string description, bool value, Action<bool> changed)
    {
        var toggle = new ToggleSwitch { IsOn = value, OnContent = "Sì", OffContent = "No" };
        toggle.Toggled += (_, _) => { changed(toggle.IsOn); S.Save(); };
        Setting(title, description, toggle);
    }

    private void Action(string title, string description, string button, Action action) =>
        Setting(title, description, UI.Button(button, (_, _) => action()));
}
