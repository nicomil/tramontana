using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Privacy;

namespace WinCleaner.App.Pages;

/// <summary>Browser and Windows traces, saved Wi‑Fi networks, and which apps used the camera or microphone.</summary>
public sealed partial class PrivacyPage : Page
{
    private readonly List<(CheckBox Box, PrivacyItem Item)> _rows = [];
    private bool _busy;
    private readonly Button _clean;

    public PrivacyPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Privacy";
        DescriptionText.Text = "Cronologia, cookie e dati dei browser, file recenti e ricerche di Windows. I browser vanno chiusi; prima di cancellare righe da un database ne viene messa una copia nel Cestino. Le password salvate si possono solo contare e cancellare, mai leggere.";
        Toolbar.Children.Add(UI.Button("Analizza", async (_, _) => await ScanAsync(), glyph: ""));
        _clean = UI.Button("Pulisci i selezionati", async (_, _) => await CleanAsync(), accent: true);
        Toolbar.Children.Add(_clean);
        Footer.Children.Add(new HyperlinkButton { Content = "Impostazioni privacy di Windows", NavigateUri = new Uri("ms-settings:privacy") });
        Loaded += async (_, _) => { if (_rows.Count == 0) await ScanAsync(); };
    }

    private async Task ScanAsync()
    {
        if (_busy) return;
        _busy = true;
        Progress.Visibility = Visibility.Visible;
        try
        {
            var items = await Task.Run(PrivacyScanner.Scan);
            var uses = await Task.Run(PrivacyScanner.CapabilityUses);
            Fill(items, uses);
            StatusText.Text = $"{items.Count} elementi trovati";
        }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
        }
    }

    private void Fill(List<PrivacyItem> items, List<CapabilityUse> uses)
    {
        _rows.Clear();
        List.Items.Clear();
        foreach (var group in items.GroupBy(i => i.Profile is null || i.Owner == "Wi‑Fi" ? i.Owner : $"{i.Owner} · profilo {i.Profile}"))
        {
            List.Items.Add(UI.Header(group.Key));
            foreach (var item in group)
            {
                var box = new CheckBox { IsChecked = item.AutoSelect, MinWidth = 0 };
                _rows.Add((box, item));
                string detail = item.Kind switch
                {
                    PrivacyKind.Passwords => $"{item.Count} password · non vengono mai lette",
                    PrivacyKind.WiFi => "Dovrai reinserire la password per ricollegarti · amministratore",
                    PrivacyKind.JumpLists => "Anche gli elementi aggiunti agli elenchi della barra delle applicazioni",
                    PrivacyKind.Clipboard => "Contenuto e cronologia degli Appunti",
                    _ => item.Count == 1 ? "1 elemento" : $"{item.Count:N0} elementi",
                };
                List.Items.Add(UI.Row(box, item.Kind == PrivacyKind.WiFi ? item.Profile! : item.Kind.Title(), detail));
            }
        }
        if (uses.Count > 0)
        {
            List.Items.Add(UI.Header("App che hanno usato fotocamera, microfono o posizione"));
            foreach (var use in uses.Take(30))
                List.Items.Add(UI.Row(new FontIcon { Glyph = use.Capability == "Fotocamera" ? "" : use.Capability == "Microfono" ? "" : "", FontSize = 16 },
                    use.App, $"{use.Capability} · {(use.InUse ? "in uso ora" : use.LastUsedUtc?.ToLocalTime().ToString("d MMM yyyy HH:mm"))}"));
        }
    }

    private async Task CleanAsync()
    {
        var chosen = _rows.Where(r => r.Box.IsChecked == true).Select(r => r.Item).ToList();
        if (chosen.Count == 0 || _busy) return;
        var owners = chosen.Select(i => i.Owner).Distinct().ToList();
        if (!await Dialogs.ConfirmAsync("Pulire i dati selezionati?",
                $"{chosen.Count} elementi di {string.Join(", ", owners)}. Chiudi i browser prima di continuare: i siti ti chiederanno di nuovo l'accesso se togli i cookie.",
                "Pulisci", destructive: chosen.Any(i => i.Kind is PrivacyKind.Passwords or PrivacyKind.WiFi))) return;
        _busy = true;
        Progress.Visibility = Visibility.Visible;
        var errors = new List<string>();
        int done = 0;
        foreach (var item in chosen)
        {
            try
            {
                if (item.Action is PrivacyAction.WiFi wifi)
                {
                    var helper = await AppState.Current.EnsureHelperAsync();
                    var r = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.DeleteWiFi, Name = wifi.Profile }, CancellationToken.None);
                    if (!r.Ok) throw new PrivacyException(r.Error ?? "Non riuscito");
                }
                else
                {
                    await Task.Run(() => PrivacyCleaner.Clean(item, RemovalMode.Recycle));
                }
                done++;
            }
            catch (OperationCanceledException) { errors.Add("Richiesta di amministratore annullata"); }
            catch (Exception e) { errors.Add($"{item.Owner} – {item.Kind.Title()}: {e.Message}"); }
        }
        _busy = false;
        Progress.Visibility = Visibility.Collapsed;
        UI.Show(Bar, errors.Count == 0 ? "Pulizia completata" : "Pulizia completata in parte",
            $"{done} di {chosen.Count} elementi puliti." + (errors.Count > 0 ? " " + string.Join(" · ", errors.Distinct().Take(3)) : ""),
            errors.Count == 0 ? InfoBarSeverity.Success : InfoBarSeverity.Warning);
        await ScanAsync();
    }
}
