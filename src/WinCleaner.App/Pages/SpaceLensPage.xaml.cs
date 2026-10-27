using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.Foundation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules;

namespace WinCleaner.App.Pages;

public sealed partial class SpaceLensPage : Page
{
    private readonly List<DiskNode> _stack = [];
    private CancellationTokenSource? _cancel;
    private string? _customFolder;

    public SpaceLensPage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable))
        {
            string label = string.IsNullOrEmpty(drive.VolumeLabel) ? "Disco locale" : drive.VolumeLabel;
            DriveBox.Items.Add(new ComboBoxItem { Content = $"{label} ({drive.Name.TrimEnd('\\')}) · {Format.Bytes(drive.AvailableFreeSpace)} liberi", Tag = drive.Name });
        }
        DriveBox.Items.Add(new ComboBoxItem { Content = "Cartella utente", Tag = KnownPaths.UserProfile });
        DriveBox.SelectedIndex = 0;
        Map.NodeClicked += Open;
        Map.NodeRightClicked += (node, element, point) => ShowMenu(node, element, point);
    }

    private string Root => _customFolder ?? (DriveBox.SelectedItem as ComboBoxItem)?.Tag as string ?? KnownPaths.SystemDrive;

    private async void PickFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new Windows.Storage.Pickers.FolderPicker();
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window!));
        var folder = await picker.PickSingleFolderAsync();
        if (folder is null) return;
        _customFolder = folder.Path;
        await ScanAsync();
        _customFolder = null;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e) => await ScanAsync();
    private void Cancel_Click(object sender, RoutedEventArgs e) => _cancel?.Cancel();

    private async Task ScanAsync()
    {
        _cancel?.Cancel();
        _cancel = new CancellationTokenSource();
        var token = _cancel.Token;
        string root = Root;
        var counter = new ScanCounter();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Progress.Visibility = Visibility.Visible;
        CancelButton.Visibility = Visibility.Visible;
        ScanButton.IsEnabled = false;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        timer.Tick += (_, _) =>
        {
            var (files, bytes) = counter.Snapshot;
            StatusText.Text = $"{files:N0} file · {Format.Bytes(bytes)} · {clock.Elapsed.TotalSeconds:0} s";
        };
        timer.Start();
        try
        {
            var tree = await Task.Run(() => new SpaceLensScanner().Scan(root, counter, token), token);
            if (token.IsCancellationRequested) { StatusText.Text = "Analisi annullata"; return; }
            _stack.Clear();
            _stack.Add(tree);
            StatusText.Text = $"{counter.Snapshot.Files:N0} file analizzati in {clock.Elapsed.TotalSeconds:0.0} s";
            Show();
        }
        catch (OperationCanceledException) { StatusText.Text = "Analisi annullata"; }
        catch (Exception ex) { StatusText.Text = "Errore: " + ex.Message; }
        finally
        {
            timer.Stop();
            Progress.Visibility = Visibility.Collapsed;
            CancelButton.Visibility = Visibility.Collapsed;
            ScanButton.IsEnabled = true;
        }
    }

    private void Show()
    {
        if (_stack.Count == 0) return;
        var node = _stack[^1];
        Map.Show(node);
        Crumbs.ItemsSource = _stack.Select(n => n.Name).ToList();
        ChildList.Items.Clear();
        foreach (var child in node.Children.Take(300))
            ChildList.Items.Add(Row(child, node.Size));

        var root = _stack[0];
        if (root.Path.Length <= 3)
        {
            var (total, free) = SpaceLensScanner.DriveSpace(root.Path);
            long hidden = total - free - root.Size;
            FooterText.Text = $"Unità: {Format.Bytes(total - free)} usati di {Format.Bytes(total)}." +
                (hidden > 1_000_000_000 ? $" {Format.Bytes(hidden)} non si vedono: file di sistema, copie shadow e punti di ripristino, cartelle non leggibili." : "");
        }
        else FooterText.Text = $"{root.Path}: {Format.Bytes(root.Size)}";
    }

    private ListViewItem Row(DiskNode child, long parentSize)
    {
        var grid = new Grid { ColumnSpacing = 10, Padding = new Thickness(0, 4, 0, 4), Tag = child };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.Children.Add(new FontIcon { Glyph = child.IsAggregate ? "" : child.IsDirectory ? "" : "", FontSize = 16 });
        var texts = new StackPanel();
        texts.Children.Add(new TextBlock { Text = child.Name + (child.IsUnreadable ? " (non leggibile)" : ""), TextTrimming = TextTrimming.CharacterEllipsis });
        texts.Children.Add(new ProgressBar { Value = parentSize > 0 ? 100.0 * child.Size / parentSize : 0, Maximum = 100, Margin = new Thickness(0, 4, 0, 0) });
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);
        var size = new TextBlock { Text = Format.Bytes(child.Size), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(size, 2);
        grid.Children.Add(size);
        var item = new ListViewItem { Content = grid, Tag = child };
        item.RightTapped += (s, e) => ShowMenu(child, item, e.GetPosition(item));
        return item;
    }

    private void ChildList_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is FrameworkElement { Tag: DiskNode node }) Open(node);
    }

    private void Open(DiskNode node)
    {
        if (!node.IsDirectory || node.Children.Count == 0) return;
        _stack.Add(node);
        Show();
    }

    private void Crumbs_ItemClicked(BreadcrumbBar sender, BreadcrumbBarItemClickedEventArgs args)
    {
        if (args.Index < _stack.Count - 1) _stack.RemoveRange(args.Index + 1, _stack.Count - args.Index - 1);
        Show();
    }

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".md", ".csv", ".json", ".xml", ".pdf", ".rtf", ".doc", ".docx", ".odt", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff", ".svg", ".mp3", ".wav", ".flac", ".m4a", ".ogg", ".mp4", ".mkv", ".mov", ".avi", ".webm",
        ".zip", ".7z", ".rar", ".iso",
    };

    private static bool IsDocument(string path) => DocumentExtensions.Contains(Path.GetExtension(path));

    private void ShowMenu(DiskNode node, FrameworkElement target, Point point)
    {
        if (node.IsAggregate) return;
        var menu = new MenuFlyout();
        var reveal = new MenuFlyoutItem { Text = "Mostra in Esplora risorse", Icon = new FontIcon { Glyph = "" } };
        reveal.Click += (_, _) => Shell.Reveal(node.Path);
        menu.Items.Add(reveal);
        // Only documents and media open from here: "Apri" on an unknown .exe, .lnk or script would run it.
        if (!node.IsDirectory && IsDocument(node.Path))
        {
            var open = new MenuFlyoutItem { Text = "Apri", Icon = new FontIcon { Glyph = "" } };
            open.Click += (_, _) => Shell.Open(node.Path);
            menu.Items.Add(open);
        }
        var recycle = new MenuFlyoutItem { Text = "Sposta nel Cestino", Icon = new FontIcon { Glyph = "" } };
        recycle.Click += async (_, _) => await RecycleAsync(node);
        menu.Items.Add(recycle);
        menu.ShowAt(target, point);
    }

    /// <summary>Only the user's own files can be removed from here; system files go through the other screens.</summary>
    private async Task RecycleAsync(DiskNode node)
    {
        var roots = Roots.UserFiles();
        if (!roots.Any(r => PathGuard.IsStrictlyInside(node.Path, r)))
        {
            await Dialogs.InfoAsync("Non disponibile qui", "Da Analisi disco si possono togliere solo i file delle tue cartelle (Documenti, Download, Desktop…). Per file di sistema e programmi usa Pulizia sistema o Disinstallazione.");
            return;
        }
        if (!await Dialogs.ConfirmAsync("Spostare nel Cestino?", $"{node.Name} ({Format.Bytes(node.Size)}) andrà nel Cestino.", "Sposta nel Cestino")) return;
        var outcome = (await Task.Run(() => Roots.UserRemover(roots, RemovalMode.Recycle).Remove([node.Path]))).Single();
        if (!outcome.Succeeded)
        {
            await Dialogs.InfoAsync("Non spostato", $"{node.Name}: {Text.Error(outcome.Error)}.");
            return;
        }
        // Rescan the folder on screen; parents keep their old size until the next full scan.
        var current = _stack[^1];
        var refreshed = await Task.Run(() => new SpaceLensScanner().Scan(current.Path));
        _stack[^1] = new DiskNode { Path = current.Path, Name = current.Name, Size = refreshed.Size, IsDirectory = true, FileCount = refreshed.FileCount, Children = refreshed.Children };
        Show();
    }
}
