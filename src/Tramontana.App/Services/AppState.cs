using Tramontana.Core;
using Tramontana.Modules;
using Tramontana.Modules.Apps;
using Tramontana.Modules.Helper;
using Tramontana.Modules.Performance;
using Tramontana.Modules.Protection;

namespace Tramontana.App.Services;

/// <summary>Everything the screens share: settings, module states, the elevated helper, results for Health Check.</summary>
public sealed class AppState : Observable
{
    public static AppState Current { get; } = new();

    public Settings Settings { get; } = Settings.Load();
    public Dictionary<string, ModuleState> Modules { get; }

    public HelperClient? Helper { get; private set; }
    private readonly SemaphoreSlim _helperGate = new(1, 1);

    // Results used by Health Check and the menu badges.
    private IReadOnlyList<Finding>? _findings;
    private IReadOnlyList<AvailableUpdate>? _updates;
    private IReadOnlyList<StartupItem>? _startup;

    public IReadOnlyList<Finding>? Findings { get => _findings; set { if (Set(ref _findings, value)) RefreshBadges(); } }
    public IReadOnlyList<AvailableUpdate>? Updates { get => _updates; set { if (Set(ref _updates, value)) RefreshBadges(); } }
    public IReadOnlyList<StartupItem>? Startup { get => _startup; set { if (Set(ref _startup, value)) RefreshBadges(); } }

    public event Action? BadgesChanged;

    private AppState()
    {
        var large = new LargeOldFilesModule { MinimumSize = Settings.LargeFileMegabytes * 1_000_000L };
        Modules = new Dictionary<string, ModuleState>
        {
            ["system-junk"] = new(new SystemJunkModule(), "File temporanei, cache, log e dump di Windows, dei browser, delle app e degli strumenti di sviluppo. Viene preselezionato solo ciò che si ricrea da solo."),
            ["recycle-bin"] = new(new RecycleBinModule(), "Cosa c'è nel Cestino di ogni unità, con la posizione originale e la data. Lo svuotamento è definitivo."),
            ["registry"] = new(new RegistryModule(), "Solo voci che puntano a programmi e file che non esistono più. Ogni voce viene salvata in un file .reg prima di toglierla."),
            ["large-old-files"] = new(large, "File grandi nelle tue cartelle e download che non apri da tempo. Sono file tuoi: non viene preselezionato nulla."),
            ["duplicates"] = new(new DuplicatesModule(), "File identici byte per byte. Per ogni gruppo resta una copia; sono preselezionate solo le copie nei Download."),
            ["similar-images"] = new(new SimilarImagesModule(), "Foto quasi uguali: la stessa foto salvata due volte, copie ridimensionate, scatti a raffica."),
            ["installers"] = new(new InstallersModule(), "Programmi di installazione nei Download e sul Desktop. Sono preselezionati solo quelli di programmi già installati, scaricati da internet."),
            ["orphans"] = new(new OrphansModule(), "Cartelle di programmi che non risultano più installati. Controlla i nomi: nulla è preselezionato."),
        };
    }

    public void RefreshBadges() => BadgesChanged?.Invoke();

    public RemovalMode DefaultMode => Settings.DefaultMode;

    /// <summary>Starts the elevated helper if needed (one administrator prompt per session).</summary>
    public async Task<HelperClient> EnsureHelperAsync()
    {
        await _helperGate.WaitAsync();
        try
        {
            if (Helper is { IsConnected: true } running) return running;
            if (Helper is not null) await Helper.DisposeAsync();
            Helper = null;
            Helper = await HelperClient.StartAsync(CancellationToken.None);
            Raise(nameof(Helper));
            Raise(nameof(IsHelperRunning));
            return Helper;
        }
        finally
        {
            _helperGate.Release();
        }
    }

    public bool IsHelperRunning => Helper?.IsConnected == true;

    /// <summary>Removes system files and HKEY_LOCAL_MACHINE entries through the helper.</summary>
    public async Task<IReadOnlyList<RemovalOutcome>> CleanAdminItemsAsync(IReadOnlyList<ScanItem> items, RemovalMode mode)
    {
        var helper = await EnsureHelperAsync();
        var outcomes = new List<RemovalOutcome>();
        var files = items.Where(i => i.Kind == ItemKind.File).Select(i => i.Path).ToArray();
        if (files.Length > 0)
        {
            var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.Remove, Paths = files, Mode = mode }, CancellationToken.None);
            if (!response.Ok) throw new InvalidOperationException(response.Error);
            outcomes.AddRange(response.Outcomes);
        }
        var registry = items.Where(i => i.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue)
            .Select(i => new RegistryTarget(i.Path, i.Kind == ItemKind.RegistryValue ? i.ValueName ?? "" : null)).ToArray();
        if (registry.Length > 0)
        {
            var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.RemoveRegistry, Registry = registry, Mode = mode }, CancellationToken.None);
            if (!response.Ok) throw new InvalidOperationException(response.Error);
            outcomes.AddRange(response.Outcomes);
        }
        return outcomes;
    }

    public async Task ShutdownAsync()
    {
        if (Helper is not null) await Helper.DisposeAsync();
        Helper = null;
    }
}
