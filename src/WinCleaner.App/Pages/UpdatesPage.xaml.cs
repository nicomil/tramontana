using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Modules.Apps;

namespace WinCleaner.App.Pages;

/// <summary>Updates from winget, installed one by one on request.</summary>
public sealed partial class UpdatesPage : Page
{
    private readonly List<(CheckBox Box, AvailableUpdate Update, TextBlock State)> _rows = [];
    private bool _busy;
    private readonly Button _check, _install;

    public UpdatesPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Aggiornamenti";
        DescriptionText.Text = "Versioni nuove dei programmi installati, da Gestione pacchetti di Windows (winget), che verifica l'impronta di ogni installer. Gli aggiornamenti si installano solo quando lo chiedi.";
        _check = UI.Button("Controlla", async (_, _) => await CheckAsync(), glyph: "");
        _install = UI.Button("Aggiorna i selezionati", async (_, _) => await InstallAsync(), accent: true);
        Toolbar.Children.Add(_check);
        Toolbar.Children.Add(_install);
        Toolbar.Children.Add(UI.Button("Windows Update", (_, _) => Shell.Open("ms-settings:windowsupdate"), glyph: ""));
        Loaded += async (_, _) => { if (AppState.Current.Updates is null) await CheckAsync(); else Fill(AppState.Current.Updates); };
    }

    private async Task CheckAsync()
    {
        if (_busy) return;
        _busy = true;
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = "Controllo degli aggiornamenti…";
        try
        {
            var updates = await WingetUpdates.CheckAsync(CancellationToken.None);
            AppState.Current.Updates = updates;
            Fill(updates);
            StatusText.Text = updates.Count == 0 ? "Tutti i programmi sono aggiornati." : $"{updates.Count} aggiornamenti disponibili";
        }
        catch (Exception e)
        {
            StatusText.Text = "";
            UI.Show(Bar, "Controllo non riuscito", e.Message, InfoBarSeverity.Warning);
        }
        finally
        {
            _busy = false;
            Progress.Visibility = Visibility.Collapsed;
        }
    }

    private void Fill(IReadOnlyList<AvailableUpdate> updates)
    {
        _rows.Clear();
        List.Items.Clear();
        foreach (var u in updates)
        {
            var box = new CheckBox { IsChecked = true, MinWidth = 0 };
            var state = UI.Caption(u.Source == "msstore" ? "Microsoft Store" : "winget");
            _rows.Add((box, u, state));
            List.Items.Add(UI.Row(box, u.Name, $"{u.InstalledVersion} → {u.AvailableVersion} · {u.Id}", state));
        }
        _install.IsEnabled = updates.Count > 0;
    }

    private async Task InstallAsync()
    {
        var chosen = _rows.Where(r => r.Box.IsChecked == true).ToList();
        if (chosen.Count == 0 || _busy) return;
        if (!await Dialogs.ConfirmAsync("Aggiornare?", $"{chosen.Count} programmi verranno aggiornati uno alla volta. Chiudili prima: alcuni installer li chiudono da soli. Windows può chiedere il permesso di amministratore.", "Aggiorna")) return;
        _busy = true;
        _install.IsEnabled = _check.IsEnabled = false;
        Progress.Visibility = Visibility.Visible;
        int ok = 0;
        foreach (var (box, update, state) in chosen)
        {
            state.Text = "Aggiornamento in corso…";
            StatusText.Text = $"Aggiornamento di {update.Name}…";
            var error = await WingetUpdates.UpgradeAsync(update.Id, CancellationToken.None);
            state.Text = error is null ? "Aggiornato" : "Non riuscito: " + error;
            if (error is null) { ok++; box.IsChecked = false; box.IsEnabled = false; }
            WinCleaner.Core.OperationLog.Standard.Write($"update\t{(error is null ? "OK" : "ERR " + error)}\t{update.Id}");
        }
        _busy = false;
        _install.IsEnabled = _check.IsEnabled = true;
        Progress.Visibility = Visibility.Collapsed;
        StatusText.Text = "";
        UI.Show(Bar, "Aggiornamenti terminati", $"{ok} di {chosen.Count} programmi aggiornati.", ok == chosen.Count ? InfoBarSeverity.Success : InfoBarSeverity.Warning);
    }
}
