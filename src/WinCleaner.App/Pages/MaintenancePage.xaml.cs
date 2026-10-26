using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinCleaner.App.Services;
using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Performance;

namespace WinCleaner.App.Pages;

/// <summary>Maintenance tasks; the ones that need administrator rights go through the helper.</summary>
public sealed partial class MaintenancePage : Page
{
    private static readonly Dictionary<MaintenanceTask, MaintenanceKind> HelperTasks = new()
    {
        [MaintenanceTask.FlushDns] = MaintenanceKind.FlushDns,
        [MaintenanceTask.FreeMemory] = MaintenanceKind.FreeMemory,
        [MaintenanceTask.WindowsCleanup] = MaintenanceKind.WindowsCleanup,
        [MaintenanceTask.ComponentCleanup] = MaintenanceKind.ComponentCleanup,
        [MaintenanceTask.SystemFileCheck] = MaintenanceKind.SystemFileCheck,
        [MaintenanceTask.RepairImage] = MaintenanceKind.RepairImage,
        [MaintenanceTask.DeliveryOptimization] = MaintenanceKind.DeliveryOptimization,
        [MaintenanceTask.OptimizeDrives] = MaintenanceKind.OptimizeDrives,
        [MaintenanceTask.RestorePoint] = MaintenanceKind.RestorePoint,
    };

    public MaintenancePage()
    {
        InitializeComponent();
        NavigationCacheMode = NavigationCacheMode.Required;
        TitleText.Text = "Manutenzione";
        DescriptionText.Text = "Operazioni di Windows raccolte in un posto. Quelle con lo scudo chiedono l'amministratore; quelle lunghe possono richiedere decine di minuti.";
        foreach (var info in Maintenance.All) List.Items.Add(Row(info));
        Loaded += async (_, _) =>
        {
            long old = await Task.Run(Maintenance.PreviousWindowsSize);
            if (old > 0) StatusText.Text = $"Windows.old occupa {Format.Bytes(old)}: «Pulizia di Windows» lo toglie.";
        };
    }

    private FrameworkElement Row(MaintenanceInfo info)
    {
        var state = UI.Caption("");
        var ring = new ProgressRing { IsActive = false, Width = 20, Height = 20 };
        Button? run = null;
        run = UI.Button("Esegui", async (_, _) => await RunAsync(info, run!, ring, state));
        var lead = new FontIcon { Glyph = info.NeedsAdmin ? "" : "", FontSize = 18 };
        var subtitle = info.Description + (info.IsLong ? " · richiede tempo" : "");
        var row = UI.Row(lead, info.Title, subtitle, state, ring, run);
        return row;
    }

    private async Task RunAsync(MaintenanceInfo info, Button run, ProgressRing ring, TextBlock state)
    {
        if (info.Confirm is { } warning && !await Dialogs.ConfirmAsync(info.Title + "?", warning, "Esegui", destructive: true)) return;
        run.IsEnabled = false;
        ring.IsActive = true;
        state.Text = "In corso…";
        try
        {
            string result;
            if (info.NeedsAdmin && HelperTasks.TryGetValue(info.Task, out var kind))
            {
                var helper = await AppState.Current.EnsureHelperAsync();
                var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.Maintenance, Task = kind }, CancellationToken.None);
                result = response.Ok ? response.Text ?? "Completato" : "Non riuscito: " + response.Error;
            }
            else
            {
                result = await Task.Run(() => Maintenance.RunAsync(info.Task, CancellationToken.None));
            }
            state.Text = result;
        }
        catch (OperationCanceledException) { state.Text = "Richiesta di amministratore annullata"; }
        catch (Exception e) { state.Text = "Non riuscito: " + e.Message; }
        finally
        {
            run.IsEnabled = true;
            ring.IsActive = false;
        }
    }
}
