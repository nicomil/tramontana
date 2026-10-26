using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using WinCleaner.App.Services;

namespace WinCleaner.App;

public partial class App : Application
{
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hwnd, string text, string caption, uint type);

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
        try
        {
            Window = new MainWindow();
        }
        catch (Exception e)
        {
            // Never stay alive without a window: it would swallow every later launch.
            WinCleaner.Core.OperationLog.Standard.Write($"app\tstartup\t{e}");
            MessageBoxW(IntPtr.Zero, $"WinCleaner non riesce ad aprire la finestra:\n\n{e.Message}\n\nDettagli nel registro delle operazioni.", "WinCleaner", 0x10);
            Exit();
            return;
        }
        if (!commandLine.Contains("--background")) Window.Activate();
    }
}
