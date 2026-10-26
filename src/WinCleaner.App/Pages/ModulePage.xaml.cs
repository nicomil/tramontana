using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinCleaner.App.Services;
using WinCleaner.Core;

namespace WinCleaner.App.Pages;

/// <summary>Scan, review and clean screen shared by the file modules.</summary>
public sealed partial class ModulePage : Page
{
    public ModuleState State { get; private set; } = null!;
    private RemovalMode _lastMode;

    public ModulePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        State = AppState.Current.Modules[(string)e.Parameter];
        TitleText.Text = State.Module.Title;
        DescriptionText.Text = State.Description;
        EmptyIcon.Glyph = State.Module.Id switch
        {
            "recycle-bin" => "", "registry" => "", "large-old-files" => "", "duplicates" => "",
            "similar-images" => "", "installers" => "", "orphans" => "", _ => "",
        };
        bool permanent = State.Module.Id is "recycle-bin" or "registry";
        ModeBox.Visibility = permanent ? Visibility.Collapsed : Visibility.Visible;
        ModeBox.Items.Clear();
        foreach (var mode in new[] { RemovalMode.Recycle, RemovalMode.DryRun, RemovalMode.Delete })
            ModeBox.Items.Add(new ComboBoxItem { Content = Text.Mode(mode), Tag = mode });
        ModeBox.SelectedIndex = AppState.Current.DefaultMode switch { RemovalMode.DryRun => 1, RemovalMode.Delete => 2, _ => 0 };
        CleanLabel.Text = State.Module.Id switch { "recycle-bin" => "Svuota", "registry" => "Correggi", _ => "Pulisci" };
        UnlockButton.Visibility = State.Module.Id == "system-junk" && !AppState.Current.IsHelperRunning ? Visibility.Visible : Visibility.Collapsed;
        State.PropertyChanged += State_PropertyChanged;
        Refresh();
        Bindings.Update();
        if (State.Report is null && !State.IsBusy) _ = State.ScanAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        State.PropertyChanged -= State_PropertyChanged;
    }

    private void State_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ModuleState.Notes) or nameof(ModuleState.HasResults) or nameof(ModuleState.Phase)) Refresh();
        if (e.PropertyName == nameof(ModuleState.LastCleanSummary) && State.LastCleanSummary is { } summary)
        {
            CleanBar.Message = summary;
            CleanBar.Title = _lastMode == RemovalMode.DryRun ? "Prova completata (nulla è stato rimosso)" : "Pulizia completata";
            OpenBinButton.Visibility = _lastMode == RemovalMode.Recycle && State.Module.Id is not ("recycle-bin" or "registry") ? Visibility.Visible : Visibility.Collapsed;
            CleanBar.IsOpen = true;
        }
    }

    private void Refresh()
    {
        GroupedCategories.Source = State.Categories.GroupBy(c => c.GroupTitle).Select(g => new CategoryGroup(g.Key, g)).ToList();
        NotesList.ItemsSource = State.Notes;
        ScanLabel.Text = State.Report is null ? "Analizza" : "Analizza di nuovo";
        if (State.SelectedCategory is null && State.Categories.Count > 0) State.SelectedCategory = State.Categories[0];
        DispatcherQueue.TryEnqueue(() => CategoryList.SelectedItem = State.SelectedCategory);
    }

    private void CategoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CategoryList.SelectedItem is CategoryViewModel category) State.SelectedCategory = category;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        CleanBar.IsOpen = false;
        await State.ScanAsync();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => State.Cancel();

    private async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await AppState.Current.EnsureHelperAsync();
            UnlockButton.Visibility = Visibility.Collapsed;
            await State.ScanAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { await Dialogs.InfoAsync("Funzioni di sistema non disponibili", ex.Message); }
    }

    private RemovalMode SelectedMode => State.Module.Id is "recycle-bin" or "registry"
        ? RemovalMode.Delete
        : (ModeBox.SelectedItem as ComboBoxItem)?.Tag is RemovalMode m ? m : RemovalMode.Recycle;

    private async void Clean_Click(object sender, RoutedEventArgs e)
    {
        var mode = SelectedMode;
        var items = State.SelectedItems();
        int admin = items.Count(i => i.NeedsAdmin);
        string what = $"{items.Count} elementi, {Format.Bytes(items.Sum(i => i.Size))}.";
        string how = State.Module.Id switch
        {
            "recycle-bin" => "Gli elementi verranno eliminati definitivamente.",
            "registry" => "Ogni voce viene prima salvata in un file .reg nella cartella Backup di WinCleaner: un doppio clic la ripristina.",
            _ => mode switch
            {
                RemovalMode.Recycle => "Andranno nel Cestino: puoi ripristinarli finché non lo svuoti.",
                RemovalMode.Delete => "Verranno eliminati definitivamente, senza passare dal Cestino.",
                _ => "Modalità Prova: non verrà rimosso nulla, vedrai solo quanto si libererebbe.",
            },
        };
        string adminText = admin > 0 ? $"\n\n{admin} elementi sono di sistema: Windows chiederà il permesso di amministratore." : "";
        bool destructive = mode == RemovalMode.Delete || State.Module.Id == "recycle-bin";
        if (!await Dialogs.ConfirmAsync($"{CleanLabel.Text}?", $"{what}\n{how}{adminText}", CleanLabel.Text, destructive)) return;
        _lastMode = mode;
        CleanBar.IsOpen = false;
        await State.CleanAsync(mode);
    }

    private void OpenBin_Click(object sender, RoutedEventArgs e) => Shell.OpenRecycleBin();
    private void SelectAll_Click(object sender, RoutedEventArgs e) => State.SelectAll(true);
    private void SelectNone_Click(object sender, RoutedEventArgs e) => State.SelectAll(false);
    private void SelectDefault_Click(object sender, RoutedEventArgs e) => State.SelectDefault();

    private void Item_RightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ItemViewModel vm) return;
        var item = vm.Item;
        var menu = new MenuFlyout();
        if (item.Kind == ItemKind.File)
        {
            var reveal = new MenuFlyoutItem { Text = "Mostra in Esplora risorse", Icon = new FontIcon { Glyph = "" } };
            reveal.Click += (_, _) => Shell.Reveal(State.Module.Id == "recycle-bin" ? item.Path : item.Path);
            menu.Items.Add(reveal);
        }
        else if (item.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue)
        {
            var open = new MenuFlyoutItem { Text = "Apri nell'Editor del Registro", Icon = new FontIcon { Glyph = "" } };
            open.Click += (_, _) => Shell.OpenRegistryKey(item.Path);
            menu.Items.Add(open);
        }
        var copy = new MenuFlyoutItem { Text = "Copia il percorso", Icon = new FontIcon { Glyph = "" } };
        copy.Click += (_, _) =>
        {
            var data = new DataPackage();
            data.SetText(item.Kind == ItemKind.RegistryValue ? $"{item.Path} [{item.ValueName}]" : item.Path);
            Clipboard.SetContent(data);
        };
        menu.Items.Add(copy);
        menu.ShowAt((FrameworkElement)sender, e.GetPosition((FrameworkElement)sender));
    }
}
