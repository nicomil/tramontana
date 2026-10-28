using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using Tramontana.App.Services;

namespace Tramontana.App;

public partial class App : Application
{
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hwnd, string text, string caption, uint type);

    public static MainWindow? Window { get; private set; }

    public App()
    {
        // Before anything opens the data folder: up to 0.2 it was %LOCALAPPDATA%\WinCleaner.
        string? migrated = Tramontana.Core.LegacyData.MigrateUser();
        InitializeComponent();
        if (migrated is not null) Tramontana.Core.OperationLog.Standard.Write($"migrazione\t{migrated}");
        UnhandledException += (_, e) =>
        {
            // Logged and kept alive: an error in one screen must not close the app mid-clean.
            Tramontana.Core.OperationLog.Standard.Write($"app\terror\t{e.Exception}");
            e.Handled = true;
        };
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        var commandLine = Environment.GetCommandLineArgs();
        if (commandLine.Contains("--scheduled-scan"))
        {
            await ScheduledScan.RunAsync();
            Exit();
            return;
        }

        // One window only: a second launch brings the first one forward.
        var main = AppInstance.FindOrRegisterForKey("Tramontana-main");
        if (!main.IsCurrent)
        {
            await main.RedirectActivationToAsync(AppInstance.GetCurrent().GetActivatedEventArgs());
            Exit();
            return;
        }
        main.Activated += (_, _) => Window?.DispatcherQueue.TryEnqueue(() => { Window.AppWindow.Show(); Window.Activate(); });

        Notifications.Register();
        int tour = Array.IndexOf(commandLine, "--tour");
        string? tourFolder = tour >= 0 && tour + 1 < commandLine.Length ? commandLine[tour + 1] : null;
        MainWindow.Scripted = commandLine.Contains("--smoke") || tourFolder is not null;
        try
        {
            Window = new MainWindow();
        }
        catch (Exception e)
        {
            // Never stay alive without a window: it would swallow every later launch.
            Tramontana.Core.OperationLog.Standard.Write($"app\tstartup\t{e}");
            MessageBoxW(IntPtr.Zero, $"Tramontana non riesce ad aprire la finestra:\n\n{e.Message}\n\nDettagli nel registro delle operazioni.", "Tramontana", 0x10);
            Exit();
            return;
        }
        if (!commandLine.Contains("--background")) Window.Activate();
        if (commandLine.Contains("--smoke")) _ = Window.SmokeAsync();
        else if (tourFolder is not null) _ = Window.TourAsync(tourFolder);
    }
}
