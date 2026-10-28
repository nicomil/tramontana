using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Tramontana.App.Services;
using Tramontana.Core;
using Tramontana.Modules;

namespace Tramontana.App.Pages;

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
        Setting("Analisi pianificata", "Cerca i file inutili e controlla la Protezione: notifica se c'è più di 500 MB da liberare o se compare un nuovo pericolo. Non rimuove nulla da sola.", schedule);

        Toggle("Icona nell'area di notifica", "Mostra CPU, memoria e disco e offre le azioni rapide.", S.TrayIcon, v => { S.TrayIcon = v; App.Window?.EnableTray(v); });
        Toggle("Chiudendo la finestra resta nell'area di notifica", "Altrimenti chiudere la finestra esce dall'app.", S.CloseToTray, v => S.CloseToTray = v);
        Toggle("Avvia con Windows", "Parte nell'area di notifica, senza aprire la finestra.", S.StartWithWindows, v => { S.StartWithWindows = v; StartWithWindows.Apply(v); });

        Section("Firme malware (Protezione)");
        Panel.Children.Add(new TextBlock { Style = UI.Style("Caption"), TextWrapping = TextWrapping.Wrap, MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left,
            Text = "Tramontana non scarica nulla. Aggiungi qui l'elenco LOLDrivers (drivers.json), l'esportazione di MalwareBazaar (CSV di hash SHA-256), set di regole YARA (.yar) e yara64.exe dalla pagina delle release ufficiali: le regole di base di Tramontana funzionano solo con yara64.exe presente. Confronta lo SHA-256 mostrato con quello pubblicato." });
        RulesList = new StackPanel { Spacing = 4 };
        Panel.Children.Add(RulesList);
        FillRules();
        var rulesButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        rulesButtons.Children.Add(UI.Button("Aggiungi file…", async (_, _) => await AddRulesAsync()));
        rulesButtons.Children.Add(new HyperlinkButton { Content = "LOLDrivers", NavigateUri = new Uri("https://www.loldrivers.io/api/") });
        rulesButtons.Children.Add(new HyperlinkButton { Content = "MalwareBazaar", NavigateUri = new Uri("https://bazaar.abuse.ch/export/") });
        rulesButtons.Children.Add(new HyperlinkButton { Content = "YARA-Forge", NavigateUri = new Uri("https://github.com/YARAHQ/yara-forge/releases") });
        rulesButtons.Children.Add(new HyperlinkButton { Content = "YARA (yara64.exe)", NavigateUri = new Uri("https://github.com/VirusTotal/yara/releases") });
        Panel.Children.Add(rulesButtons);

        Section("Sicurezza e registri");
        Action("Registro delle operazioni", "Ogni file rimosso, spostato o saltato, con data ed esito.", "Apri", () => Shell.Reveal(OperationLog.Standard.FilePath));
        Action("Backup del registro di sistema", "File .reg salvati prima di ogni modifica: un doppio clic ripristina le voci. Quelli delle operazioni da amministratore stanno in " + Path.Combine(DataFolders.HelperRoot, "Backups") + " (accessibile solo agli amministratori).", "Apri cartella", () =>
        {
            var folder = Path.Combine(DataFolders.UserRoot, "Backups");
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
        Panel.Children.Add(new TextBlock { Text = $"Tramontana {typeof(App).Assembly.GetName().Version?.ToString(3)} · uso personale", Style = UI.Style("Caption") });
    }

    private StackPanel? RulesList;

    private void FillRules()
    {
        if (RulesList is null) return;
        RulesList.Children.Clear();
        var store = new Tramontana.Modules.Protection.Rules.RuleStore();
        var files = store.Files();
        var pins = Tramontana.Modules.Protection.Rules.RulePins.Load();
        if (files.Count == 0) RulesList.Children.Add(new TextBlock { Text = "Nessun file aggiunto: attivi solo i controlli senza firme.", Style = UI.Style("Caption") });
        foreach (var file in files)
        {
            var remove = UI.Button("Rimuovi", async (_, _) =>
            {
                try { store.Remove(file); await PinAsync(); } catch (Exception e) { _ = Dialogs.InfoAsync("Non rimosso", e.Message); }
                FillRules();
            });
            string verdict = Tramontana.Modules.Protection.Rules.RulePins.Check(pins, file) switch
            {
                Tramontana.Modules.Protection.Rules.RulePins.Verdict.Confirmed => "confermato",
                Tramontana.Modules.Protection.Rules.RulePins.Verdict.Changed => "CAMBIATO dopo la conferma: non viene usato",
                _ => "non confermato come amministratore",
            };
            var row = UI.Row(null, file.Name, $"{file.Kind} · {Format.Bytes(file.Size)} · {verdict}\nSHA-256 {file.Sha256}", remove);
            RulesList.Children.Add(new Border { Style = UI.Style("Card"), Child = row, Padding = new Thickness(12, 8, 12, 8) });
        }
        if (files.Count > 0 && files.Any(f => Tramontana.Modules.Protection.Rules.RulePins.Check(pins, f) != Tramontana.Modules.Protection.Rules.RulePins.Verdict.Confirmed))
            RulesList.Children.Add(UI.Button("Conferma i file come amministratore", async (_, _) => { await PinAsync(); FillRules(); }));
    }

    /// <summary>The hashes of the files go to the administrator-only pins folder (one UAC prompt per session).</summary>
    private async Task PinAsync()
    {
        try { await ProtectionActions.PinRulesAsync(); }
        catch (OperationCanceledException) { await Dialogs.InfoAsync("File non confermati", "Senza la conferma da amministratore le regole restano modificabili da qualsiasi programma che gira con i tuoi diritti: la Protezione lo segnala."); }
        catch (Exception e) { await Dialogs.InfoAsync("Conferma non riuscita", e.Message); }
    }

    private async Task AddRulesAsync()
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        foreach (var ext in new[] { ".yar", ".yara", ".csv", ".txt", ".json", ".exe" }) picker.FileTypeFilter.Add(ext);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window!));
        var picked = await picker.PickMultipleFilesAsync();
        if (picked is null || picked.Count == 0) return;
        var store = new Tramontana.Modules.Protection.Rules.RuleStore();
        var problems = new List<string>();
        foreach (var file in picked)
        {
            try { await Task.Run(() => store.Add(file.Path)); }
            catch (Exception e) { problems.Add($"{file.Name}: {e.Message}"); }
        }
        if (problems.Count < picked.Count) await PinAsync();
        FillRules();
        if (problems.Count > 0) await Dialogs.InfoAsync("Alcuni file non sono stati aggiunti", string.Join("\n", problems));
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
