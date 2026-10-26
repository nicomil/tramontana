using System.Collections.ObjectModel;
using System.Diagnostics;
using Microsoft.UI.Xaml;
using WinCleaner.Core;
using WinCleaner.Modules;
using WinCleaner.Modules.Helper;

namespace WinCleaner.App.Services;

public sealed class ItemViewModel : Observable
{
    public ScanItem Item { get; }
    public CategoryViewModel Category { get; }
    private bool _isChecked;

    public ItemViewModel(ScanItem item, CategoryViewModel category, bool isChecked)
    {
        Item = item;
        Category = category;
        _isChecked = isChecked;
    }

    public bool IsKept => Category.Keep is { } keep && string.Equals(keep, Item.Path, StringComparison.OrdinalIgnoreCase);

    public bool IsChecked
    {
        get => _isChecked;
        set
        {
            if (value && IsKept) value = false;
            if (Set(ref _isChecked, value)) Category.ItemChanged();
        }
    }

    internal void SetSilently(bool value)
    {
        if (value && IsKept) value = false;
        if (_isChecked == value) return;
        _isChecked = value;
        Raise(nameof(IsChecked));
    }

    public string Name => Item.DisplayName;
    public string Detail => Item.Detail ?? Item.Path;
    public string SizeText => Item.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue ? "registro" : Format.Bytes(Item.Size);
    public Visibility AdminVisibility => Item.NeedsAdmin ? Visibility.Visible : Visibility.Collapsed;
    public Visibility KeptVisibility => IsKept ? Visibility.Visible : Visibility.Collapsed;
    public bool CanCheck => !IsKept;
    public string RiskGlyph => Item.Risk switch { RiskLevel.High => "", RiskLevel.Medium => "", _ => "" };
    public string RiskText => Item.Risk switch { RiskLevel.High => "Attenzione: possibile perdita di dati", RiskLevel.Medium => "Si perde qualche impostazione o va riscaricato", _ => "" };
    public Visibility RiskVisibility => Item.Risk == RiskLevel.Low ? Visibility.Collapsed : Visibility.Visible;
}

public sealed class CategoryViewModel : Observable
{
    public ScanCategory Category { get; }
    public List<ItemViewModel> Items { get; }
    private readonly ModuleState _owner;

    public CategoryViewModel(ScanCategory category, ModuleState owner, ISet<string> selected)
    {
        Category = category;
        _owner = owner;
        Items = [.. category.Items.Select(i => new ItemViewModel(i, this, selected.Contains(i.Key)))];
    }

    public string? Keep => Category.Keep;
    public string Title => Category.Title;
    public string? Description => Category.Description;
    public Visibility DescriptionVisibility => string.IsNullOrEmpty(Category.Description) ? Visibility.Collapsed : Visibility.Visible;
    public string GroupTitle => ModuleState.GroupTitle(Category.Group);
    public string SizeText => Category.Items.All(i => i.Kind != ItemKind.File) ? $"{Items.Count} voci" : Format.Bytes(Category.TotalSize);
    public string CountText => Items.Count == 1 ? "1 elemento" : $"{Items.Count} elementi";
    public Visibility AdminVisibility => Category.Items.Any(i => i.NeedsAdmin) ? Visibility.Visible : Visibility.Collapsed;

    public long SelectedSize => Items.Where(i => i.IsChecked).Sum(i => i.Item.Size);
    public int SelectedCount => Items.Count(i => i.IsChecked);

    /// <summary>Three states for display: all, none, some (null).</summary>
    public bool? IsChecked
    {
        get
        {
            int n = SelectedCount;
            int checkable = Items.Count(i => i.CanCheck);
            return n == 0 ? false : n == checkable ? true : null;
        }
    }

    public void SetAll(bool value)
    {
        foreach (var item in Items) item.SetSilently(value);
        ItemChanged();
    }

    /// <summary>User click: a fully selected category is cleared, otherwise everything is selected.</summary>
    public void Toggle() => SetAll(IsChecked != true);

    internal void ItemChanged()
    {
        Raise(nameof(IsChecked));
        Raise(nameof(SelectedSummary));
        _owner.SelectionChanged();
    }

    public string SelectedSummary => SelectedCount == 0 ? CountText : $"{SelectedCount} di {Items.Count} · {Format.Bytes(SelectedSize)}";
}

public enum ModulePhase { Idle, Scanning, Ready, Cleaning }

/// <summary>Scan, review and clean state of one file module; kept across page navigation.</summary>
public sealed class ModuleState : Observable
{
    public ICleanerModule Module { get; }
    public string Description { get; }
    public ObservableCollection<CategoryViewModel> Categories { get; } = [];
    private ScanReport? _report;
    private ModulePhase _phase;
    private string _status = "";
    private string? _lastCleanSummary;
    private CancellationTokenSource? _cancel;
    private CategoryViewModel? _selectedCategory;
    private string _filter = "";

    public ModuleState(ICleanerModule module, string description)
    {
        Module = module;
        Description = description;
    }

    public ScanReport? Report => _report;
    public ModulePhase Phase { get => _phase; private set { if (Set(ref _phase, value)) { Raise(nameof(IsBusy)); Raise(nameof(CanClean)); Raise(nameof(HasResults)); } } }
    public bool IsBusy => Phase is ModulePhase.Scanning or ModulePhase.Cleaning;
    public bool HasResults => Categories.Count > 0;
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string? LastCleanSummary { get => _lastCleanSummary; private set => Set(ref _lastCleanSummary, value); }
    public IReadOnlyList<string> Notes => _report?.Notes ?? [];

    public CategoryViewModel? SelectedCategory
    {
        get => _selectedCategory;
        set { if (Set(ref _selectedCategory, value)) Raise(nameof(VisibleItems)); }
    }

    public string Filter
    {
        get => _filter;
        set { if (Set(ref _filter, value)) Raise(nameof(VisibleItems)); }
    }

    /// <summary>Items of the selected category that match the filter.</summary>
    public IEnumerable<ItemViewModel> VisibleItems => SelectedCategory?.Items.Where(i =>
        _filter.Length == 0 || i.Name.Contains(_filter, StringComparison.OrdinalIgnoreCase) || i.Detail.Contains(_filter, StringComparison.OrdinalIgnoreCase)) ?? [];

    public long SelectedSize => Categories.Sum(c => c.SelectedSize);
    public int SelectedCount => Categories.Sum(c => c.SelectedCount);
    public bool CanClean => Phase == ModulePhase.Ready && SelectedCount > 0;
    public string SelectionText => SelectedCount == 0 ? "Nessun elemento scelto" : $"{SelectedCount} elementi scelti · {Format.Bytes(SelectedSize)}";

    /// <summary>Badge for the navigation menu after a scan.</summary>
    public string? Badge => _report is null ? null : _report.TotalSize > 0 ? Format.Bytes(_report.TotalSize) : _report.AllItems.Any() ? _report.AllItems.Count().ToString() : null;

    internal void SelectionChanged()
    {
        Raise(nameof(SelectedSize));
        Raise(nameof(SelectedCount));
        Raise(nameof(CanClean));
        Raise(nameof(SelectionText));
    }

    public static string GroupTitle(string group) => group switch
    {
        "windows" => "Windows",
        "system" => "Sistema (amministratore)",
        "browsers" => "Browser",
        "apps" => "App",
        "developer" => "Strumenti di sviluppo",
        "bins" => "Cestini",
        "downloads" => "Download",
        "large" => "File grandi",
        "duplicates" => "Copie",
        "similar" => "Immagini simili",
        "installers" => "Installer",
        "orphans" => "Avanzi",
        "registry" => "Registro",
        "leftovers" => "Avanzi del programma",
        _ => "",
    };

    public void Cancel() => _cancel?.Cancel();

    public async Task ScanAsync()
    {
        if (IsBusy) return;
        _cancel = new CancellationTokenSource();
        var token = _cancel.Token;
        Phase = ModulePhase.Scanning;
        LastCleanSummary = null;
        var clock = Stopwatch.StartNew();
        var progress = new Progress<string>(s => Status = s);
        Status = "Analisi in corso…";
        try
        {
            var report = await Module.ScanAsync(progress, token);
            // System folders are read by the helper when it is already running.
            if (Module is SystemJunkModule && AppState.Current.Helper is { IsConnected: true } helper)
            {
                var system = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.ScanSystemJunk }, token);
                if (system.Ok && system.Report is { } admin)
                {
                    var userCategories = report.Categories.Where(c => c.Group != "system");
                    report = report with
                    {
                        Categories = [.. userCategories, .. admin.Categories],
                    } ;
                    report = report with { Notes = [.. report.Notes.Where(n => !n.Contains("amministratore"))] };
                }
            }
            if (token.IsCancellationRequested) return;
            Apply(report);
            Status = $"Analisi completata in {clock.Elapsed.TotalSeconds:0.0} s";
        }
        catch (OperationCanceledException)
        {
            Status = "Analisi annullata";
        }
        catch (Exception e)
        {
            Status = "Errore: " + e.Message;
        }
        finally
        {
            Phase = _report is null ? ModulePhase.Idle : ModulePhase.Ready;
            AppState.Current.RefreshBadges();
        }
    }

    private void Apply(ScanReport report)
    {
        _report = report;
        var selected = Selection.Default(report);
        Categories.Clear();
        foreach (var category in report.Categories) Categories.Add(new CategoryViewModel(category, this, selected));
        SelectedCategory = Categories.FirstOrDefault();
        Raise(nameof(Notes));
        Raise(nameof(HasResults));
        Raise(nameof(Badge));
        SelectionChanged();
    }

    public void SelectAll(bool value)
    {
        foreach (var c in Categories) c.SetAll(value);
    }

    /// <summary>Restores the preselection of the last scan.</summary>
    public void SelectDefault()
    {
        if (_report is not null) Apply(_report);
    }

    public List<ScanItem> SelectedItems() => [.. Categories.SelectMany(c => c.Items).Where(i => i.IsChecked).Select(i => i.Item)];

    /// <summary>
    /// Removes the selected items. Copy groups are checked first (the kept
    /// copy must stay and still be identical), junk is rescanned so items of a
    /// program opened meanwhile are left alone, and system items go through
    /// the helper (one administrator prompt per session).
    /// </summary>
    public async Task<IReadOnlyList<RemovalOutcome>> CleanAsync(RemovalMode mode, IReadOnlyList<ScanItem>? only = null)
    {
        if (_report is null || IsBusy) return [];
        var items = only?.ToList() ?? SelectedItems();
        if (items.Count == 0) return [];

        var selectedPaths = new HashSet<string>(items.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);
        var unsafeGroups = Selection.UnsafeCopyGroups(_report, selectedPaths);
        if (unsafeGroups.Count > 0)
        {
            await Dialogs.InfoAsync("Pulizia annullata", $"In «{unsafeGroups[0].Title}» resterebbe senza copie: lascia almeno la copia da tenere.");
            return [];
        }

        Phase = ModulePhase.Cleaning;
        Status = "Pulizia in corso…";
        var outcomes = new List<RemovalOutcome>();
        try
        {
            if (Module is DuplicatesModule)
            {
                var changed = _report.Categories.Where(c => c.Keep is not null)
                    .Where(c => c.Items.Any(i => selectedPaths.Contains(i.Path)))
                    .Where(c => !DuplicatesModule.StillDuplicates(c.Items.Where(i => selectedPaths.Contains(i.Path)).Select(i => i.Path), c.Keep!))
                    .ToList();
                if (changed.Count > 0)
                {
                    foreach (var c in changed) foreach (var i in c.Items) selectedPaths.Remove(i.Path);
                    items = [.. items.Where(i => selectedPaths.Contains(i.Path))];
                    Status = $"{changed.Count} gruppi di copie sono cambiati dopo l'analisi e sono stati lasciati stare";
                }
            }

            if (Module is SystemJunkModule)
            {
                // Programs opened after the scan: their caches are skipped now.
                var fresh = await Module.ScanAsync(null, CancellationToken.None);
                var stillJunk = new HashSet<string>(fresh.AllItems.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);
                items = [.. items.Where(i => i.NeedsAdmin || stillJunk.Contains(i.Path))];
            }

            var user = items.Where(i => !i.NeedsAdmin).ToList();
            var admin = items.Where(i => i.NeedsAdmin).ToList();
            outcomes.AddRange(await Task.Run(() => Cleaner.CleanUserItems(Module, user, mode)));
            if (admin.Count > 0) outcomes.AddRange(await AppState.Current.CleanAdminItemsAsync(admin, mode));
        }
        catch (OperationCanceledException)
        {
            Status = "Richiesta di amministratore annullata";
        }
        catch (Exception e)
        {
            Status = "Errore: " + e.Message;
        }
        finally
        {
            Phase = ModulePhase.Ready;
        }

        if (outcomes.Count > 0)
        {
            LastCleanSummary = Text.Summary(outcomes, mode);
            Status = "";
            // Removed items leave the list; the rest stays for another try.
            if (mode != RemovalMode.DryRun)
            {
                var gone = new HashSet<string>(outcomes.Where(o => o.Succeeded && o.InUse == 0).Select(o => o.Path), StringComparer.OrdinalIgnoreCase);
                var remaining = _report.Categories
                    .Select(c => c with { Items = [.. c.Items.Where(i => !gone.Contains(i.Path) && !gone.Contains(new RegistryTarget(i.Path, i.ValueName).ToString()))] })
                    .Where(c => c.Items.Count > 0 && (c.Keep is null || c.Items.Count > 1))
                    .ToList();
                Apply(_report with { Categories = remaining });
            }
        }
        AppState.Current.RefreshBadges();
        return outcomes;
    }
}
