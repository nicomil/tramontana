using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Modules.Protection;

namespace WinCleaner.App.Pages;

/// <summary>What Protection put aside: restore it or delete it for good.</summary>
public sealed partial class QuarantinePage : Page
{
    public QuarantinePage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Disabled;
        TitleText.Text = "Quarantena";
        DescriptionText.Text = "I file messi in quarantena da Protezione: senza permessi di esecuzione e contrassegnati come scaricati da internet. Ripristinare li rimette dov'erano; eliminare è definitivo.";
        Toolbar.Children.Add(UI.Button("Apri cartella", (_, _) => { Directory.CreateDirectory(Quarantine.UserFolder); Shell.Open(Quarantine.UserFolder); }, glyph: ""));
        Loaded += (_, _) => Fill();
    }

    private void Fill()
    {
        List.Items.Clear();
        var records = new Quarantine().Records();
        StatusText.Text = records.Count == 0 ? "Niente in quarantena." : $"{records.Count} elementi";
        foreach (var record in records)
        {
            var restore = UI.Button("Ripristina", async (_, _) => await DoAsync("Ripristino", () => ProtectionActions.RestoreAsync(record)));
            var delete = UI.Button("Elimina", async (_, _) =>
            {
                if (!await Dialogs.ConfirmAsync("Eliminare definitivamente?", record.OriginalPath, "Elimina", destructive: true)) return;
                await DoAsync("Eliminazione", () => ProtectionActions.DeleteAsync(record));
            });
            List.Items.Add(UI.Row(new FontIcon { Glyph = "", FontSize = 16 }, record.Title,
                $"{record.Reason}\n{record.OriginalPath}\n{record.Date:g}{(record.IsSystem ? " · elemento di sistema" : "")}", restore, delete));
        }
    }

    private async Task DoAsync(string title, Func<Task> action)
    {
        try { await action(); UI.Show(Bar, title, "Fatto."); }
        catch (OperationCanceledException) { }
        catch (Exception e) { UI.Show(Bar, title + " non riuscito", e.Message, InfoBarSeverity.Error); }
        Fill();
    }
}
