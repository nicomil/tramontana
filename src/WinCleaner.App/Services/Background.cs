using Microsoft.Win32;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using WinCleaner.Core;
using WinCleaner.Modules;

namespace WinCleaner.App.Services;

public static class Notifications
{
    private static bool _registered;

    public static void Register()
    {
        try
        {
            AppNotificationManager.Default.Register();
            _registered = true;
        }
        catch (Exception) { }
    }

    public static void Show(string title, string text)
    {
        try
        {
            if (!_registered) Register();
            var notification = new AppNotificationBuilder().AddText(title).AddText(text).BuildNotification();
            AppNotificationManager.Default.Show(notification);
        }
        catch (Exception) { }
    }
}

/// <summary>
/// The scan started by the scheduled task: it removes nothing, it only
/// notifies when more than 500 MB could be freed.
/// </summary>
public static class ScheduledScan
{
    public const long Threshold = 500_000_000;

    public static async Task RunAsync()
    {
        try
        {
            var report = await new SystemJunkModule().ScanAsync(null, CancellationToken.None);
            long size = report.AllItems.Where(i => i.AutoSelect && !i.NeedsAdmin).Sum(i => i.Size);
            OperationLog.Standard.Write($"scheduled\tscan\t{size}");
            if (size >= Threshold)
            {
                Notifications.Register();
                Notifications.Show("WinCleaner", $"Ci sono {Format.Bytes(size)} di file inutili. Apri WinCleaner per controllarli e pulire.");
                await Task.Delay(1500);
            }
        }
        catch (Exception e)
        {
            OperationLog.Standard.Write($"scheduled\terror\t{e.Message}");
        }
    }
}

/// <summary>The task in Task Scheduler that runs the scheduled scan as the current user, without elevation.</summary>
public static class Scheduler
{
    private const string TaskName = "WinCleaner - analisi pianificata";

    public static void Apply(string schedule)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return;
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        dynamic root = service.GetFolder(@"\");
        try { root.DeleteTask(TaskName, 0); } catch (Exception) { }
        if (schedule is not ("daily" or "weekly")) return;

        dynamic task = service.NewTask(0);
        task.RegistrationInfo.Description = "Cerca i file inutili e avvisa se c'è molto spazio da liberare. Non rimuove nulla.";
        task.Settings.StartWhenAvailable = true;
        task.Settings.DisallowStartIfOnBatteries = false;
        task.Settings.ExecutionTimeLimit = "PT30M";
        task.Principal.LogonType = 3; // TASK_LOGON_INTERACTIVE_TOKEN
        task.Principal.RunLevel = 0;  // least privilege
        dynamic trigger = task.Triggers.Create(schedule == "daily" ? 2 : 3); // DAILY or WEEKLY
        trigger.StartBoundary = DateTime.Today.AddHours(12).ToString("yyyy-MM-dd'T'HH:mm:ss");
        if (schedule == "weekly") { trigger.DaysOfWeek = 2; trigger.WeeksInterval = 1; } // Monday
        else trigger.DaysInterval = 1;
        dynamic action = task.Actions.Create(0);
        action.Path = Environment.ProcessPath;
        action.Arguments = "--scheduled-scan";
        root.RegisterTaskDefinition(TaskName, task, 6 /* CREATE_OR_UPDATE */, null, null, 3 /* INTERACTIVE_TOKEN */, null);
    }
}

/// <summary>"Avvia con Windows": a value in the user's Run key that opens the app in the notification area.</summary>
public static class StartWithWindows
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Name = "WinCleaner";

    public static void Apply(bool enabled)
    {
        using var run = Registry.CurrentUser.CreateSubKey(Key, writable: true);
        if (enabled) run.SetValue(Name, $"\"{Environment.ProcessPath}\" --background");
        else run.DeleteValue(Name, throwOnMissingValue: false);
    }
}
