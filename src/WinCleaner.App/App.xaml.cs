using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using WinCleaner.App.Services;

namespace WinCleaner.App;

public partial class App : Application
{
    public static MainWindow? Window { get; private set; }

    public App()
    {
        InitializeComponent();
        UnhandledException += (_, e) =>
        {
            // Logged and kept alive: an error in one screen must not close the app mid-clean.
            WinCleaner.Core.OperationLog.Standard.Write($"app\terror\t{e.Exception}");
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
        var main = AppInstance.FindOrRegisterForKey("WinCleaner-main");
        if (!main.IsCurrent)
        {
            await main.RedirectActivationToAsync(AppInstance.GetCurrent().GetActivatedEventArgs());
            Exit();
            return;
        }
        main.Activated += (_, _) => Window?.DispatcherQueue.TryEnqueue(() => { Window.AppWindow.Show(); Window.Activate(); });

        Notifications.Register();
        Window = new MainWindow();
        if (!commandLine.Contains("--background")) Window.Activate();
    }
}
