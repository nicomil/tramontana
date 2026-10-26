using System.Diagnostics;
using Microsoft.Win32;
using WinCleaner.Core;
using WinCleaner.Modules.Apps;

namespace WinCleaner.Modules.Performance;

public enum StartupKind { RunKey, StartupFolder, ScheduledTask, Service }

/// <summary>Something that starts with Windows or at sign-in.</summary>
public sealed record StartupItem
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required StartupKind Kind { get; init; }
    /// <summary>Where it comes from, for the user ("Registro · utente", "Attività pianificata"…).</summary>
    public required string Location { get; init; }
    public string? Command { get; init; }
    public string? Executable { get; init; }
    public bool Enabled { get; init; }
    /// <summary>The program it starts no longer exists.</summary>
    public bool IsBroken { get; init; }
    public bool NeedsAdmin { get; init; }
    public SignatureInfo? Signature { get; init; }

    public string? RegistryKey { get; init; }
    public string? ValueName { get; init; }
    /// <summary>StartupApproved key whose value (named like the entry) holds the enabled flag, as Task Manager uses.</summary>
    public string? ApprovedKey { get; init; }
    public string? FilePath { get; init; }
    public string? TaskPath { get; init; }
    public string? ServiceName { get; init; }
    /// <summary>For services: 2 automatic, 3 manual, 4 disabled.</summary>
    public int? StartType { get; init; }
    public bool DelayedStart { get; init; }
    public DateTime? LastRunUtc { get; init; }
}

/// <summary>
/// Startup programs: Run keys and Startup folders (enabled and disabled
/// through the StartupApproved keys, exactly like Task Manager, so both show
/// the same state), scheduled tasks outside \Microsoft\, and automatic
/// services not made by Microsoft.
/// </summary>
public static class StartupManager
{
    private const string Run = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Approved = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    public static List<StartupItem> List(bool includeTasks = true, bool includeServices = true)
    {
        var items = new List<StartupItem>();
        items.AddRange(RunEntries(@"HKEY_CURRENT_USER\" + Run, @"HKEY_CURRENT_USER\" + Approved + @"\Run", "Registro · utente", false));
        items.AddRange(RunEntries(@"HKEY_LOCAL_MACHINE\" + Run, @"HKEY_LOCAL_MACHINE\" + Approved + @"\Run", "Registro · tutti gli utenti", true));
        items.AddRange(RunEntries(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\" + Approved + @"\Run32", "Registro · tutti gli utenti (32 bit)", true));
        items.AddRange(FolderEntries(KnownPaths.Startup, @"HKEY_CURRENT_USER\" + Approved + @"\StartupFolder", "Esecuzione automatica · utente", false));
        items.AddRange(FolderEntries(KnownPaths.CommonStartup, @"HKEY_LOCAL_MACHINE\" + Approved + @"\StartupFolder", "Esecuzione automatica · tutti", true));
        if (includeTasks) items.AddRange(ScheduledTasks());
        if (includeServices) items.AddRange(Services());
        return items;
    }

    /// <summary>Enabled unless the StartupApproved value says otherwise (odd first byte = disabled).</summary>
    internal static bool IsApproved(string approvedKey, string name)
    {
        using var key = RegistryCleaner.Open(approvedKey, writable: false);
        return key?.GetValue(name) is not byte[] { Length: > 0 } data || (data[0] & 1) == 0;
    }

    private static IEnumerable<StartupItem> RunEntries(string keyPath, string approvedKey, string location, bool admin)
    {
        using var key = RegistryCleaner.Open(keyPath, writable: false);
        if (key is null) yield break;
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command || command.Length == 0) continue;
            var exe = ExecutableOf(command);
            yield return new StartupItem
            {
                Id = $"run|{keyPath}|{name}",
                Name = name,
                Kind = StartupKind.RunKey,
                Location = location,
                Command = command,
                Executable = exe,
                Enabled = IsApproved(approvedKey, name),
                IsBroken = exe is not null && !File.Exists(exe),
                NeedsAdmin = admin,
                Signature = exe is not null && File.Exists(exe) ? Signatures.Check(exe) : null,
                RegistryKey = keyPath,
                ValueName = name,
                ApprovedKey = approvedKey,
            };
        }
    }

    private static IEnumerable<StartupItem> FolderEntries(string folder, string approvedKey, string location, bool admin)
    {
        if (!Directory.Exists(folder)) yield break;
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            string name = Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            string? target = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? Shortcuts.Target(file) : file;
            yield return new StartupItem
            {
                Id = $"folder|{file}",
                Name = Path.GetFileNameWithoutExtension(file),
                Kind = StartupKind.StartupFolder,
                Location = location,
                Command = target,
                Executable = target,
                Enabled = IsApproved(approvedKey, name),
                IsBroken = target is not null && PathGuard.IsValidPath(target) && !File.Exists(target) && !Directory.Exists(target),
                NeedsAdmin = admin,
                Signature = target is not null && File.Exists(target) ? Signatures.Check(target) : null,
                FilePath = file,
                ApprovedKey = approvedKey,
                ValueName = name,
            };
        }
    }

    /// <summary>The executable a command line starts (quoted, unquoted with spaces, or through rundll32).</summary>
    public static string? ExecutableOf(string command)
    {
        command = Environment.ExpandEnvironmentVariables(command.Trim());
        string path;
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end < 0) return null;
            path = command[1..end];
        }
        else
        {
            int exe = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            path = exe > 0 ? command[..(exe + 4)] : command.Split(' ')[0];
        }
        if (!path.Contains('\\'))
        {
            // Bare names are looked up in System32 (rundll32.exe, ctfmon.exe…).
            var system = Path.Combine(Environment.SystemDirectory, path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? path : path + ".exe");
            return system;
        }
        return PathGuard.IsValidPath(path) ? path : null;
    }

    private static IEnumerable<StartupItem> ScheduledTasks()
    {
        var items = new List<StartupItem>();
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return items;
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            void Walk(dynamic folder)
            {
                string folderPath = folder.Path;
                if (folderPath.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase)) return;
                foreach (dynamic task in folder.GetTasks(1))
                {
                    try
                    {
                        string? exe = null, command = null;
                        foreach (dynamic action in task.Definition.Actions)
                        {
                            if ((int)action.Type != 0) continue; // TASK_ACTION_EXEC
                            string p = ((string?)action.Path ?? "").Trim().Trim('"');
                            string a = (string?)action.Arguments ?? "";
                            if (p.Length == 0) break;
                            command = (p.Contains(' ') ? $"\"{p}\"" : p) + (a.Length > 0 ? " " + a : "");
                            exe = ExecutableOf(command);
                            break;
                        }
                        DateTime? lastRun = null;
                        try { var lr = (DateTime)task.LastRunTime; if (lr.Year > 2000) lastRun = lr.ToUniversalTime(); } catch { }
                        items.Add(new StartupItem
                        {
                            Id = $"task|{(string)task.Path}",
                            Name = (string)task.Name,
                            Kind = StartupKind.ScheduledTask,
                            Location = "Attività pianificata",
                            Command = command,
                            Executable = exe,
                            Enabled = (bool)task.Enabled,
                            IsBroken = exe is not null && !File.Exists(exe),
                            NeedsAdmin = false,
                            Signature = exe is not null && File.Exists(exe) ? Signatures.Check(exe) : null,
                            TaskPath = (string)task.Path,
                            LastRunUtc = lastRun,
                        });
                    }
                    catch (Exception) { }
                }
                foreach (dynamic sub in folder.GetFolders(0)) Walk(sub);
            }
            Walk(service.GetFolder(@"\"));
        }
        catch (Exception) { }
        return items;
    }

    private static IEnumerable<StartupItem> Services()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null) yield break;
        foreach (var name in services.GetSubKeyNames())
        {
            StartupItem? item = null;
            try
            {
                using var key = services.OpenSubKey(name);
                if (key is null) continue;
                int type = key.GetValue("Type") is int t ? t : 0;
                int start = key.GetValue("Start") is int s ? s : 3;
                if ((type & 0x30) == 0 || start is not (2 or 4)) continue; // Win32 services, automatic or disabled
                if (key.GetValue("ImagePath") is not string image) continue;
                var exe = ExecutableOf(image);
                if (exe is null) continue;
                if (PathGuard.IsStrictlyInside(exe, KnownPaths.Windows)) continue;
                var signature = File.Exists(exe) ? Signatures.Check(exe) : null;
                if (signature?.IsMicrosoft == true) continue;
                string display = key.GetValue("DisplayName") as string ?? name;
                if (display.StartsWith('@')) display = name;
                item = new StartupItem
                {
                    Id = $"service|{name}",
                    Name = display,
                    Kind = StartupKind.Service,
                    Location = "Servizio",
                    Command = image,
                    Executable = exe,
                    Enabled = start == 2,
                    IsBroken = !File.Exists(exe),
                    NeedsAdmin = true,
                    Signature = signature,
                    ServiceName = name,
                    StartType = start,
                    DelayedStart = key.GetValue("DelayedAutostart") is int d && d == 1,
                };
            }
            catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException) { }
            if (item is not null) yield return item;
        }
    }

    /// <summary>
    /// Enables or disables a Run or Startup folder entry the way Task Manager
    /// does: a 12-byte StartupApproved value (02 = enabled, 03 = disabled,
    /// followed by the time it was disabled). The entry itself is untouched.
    /// </summary>
    public static void SetApproved(StartupItem item, bool enabled)
    {
        if (item.ApprovedKey is null || item.ValueName is null) throw new InvalidOperationException("Not a Run or Startup folder entry");
        var key = RegistryCleaner.Normalize(item.ApprovedKey)!;
        var hive = key.StartsWith("HKEY_CURRENT_USER", StringComparison.Ordinal) ? Registry.CurrentUser : Registry.LocalMachine;
        using var approved = hive.CreateSubKey(key[(key.IndexOf('\\') + 1)..], writable: true);
        var data = new byte[12];
        data[0] = enabled ? (byte)0x02 : (byte)0x03;
        if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
        approved.SetValue(item.ValueName, data, RegistryValueKind.Binary);
        OperationLog.Standard.Write($"startup\t{(enabled ? "enable" : "disable")}\t{item.Id}");
    }

    /// <summary>Enables or disables a scheduled task. Tasks created by an administrator need the helper.</summary>
    public static void SetTaskEnabled(string taskPath, bool enabled)
    {
        if (taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Windows tasks are not changed");
        var type = Type.GetTypeFromProgID("Schedule.Service")!;
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        string folder = taskPath[..Math.Max(1, taskPath.LastIndexOf('\\'))];
        string name = taskPath[(taskPath.LastIndexOf('\\') + 1)..];
        dynamic task = service.GetFolder(folder).GetTask(name);
        task.Enabled = enabled;
        OperationLog.Standard.Write($"task\t{(enabled ? "enable" : "disable")}\t{taskPath}");
    }

    /// <summary>Deletes a scheduled task (not under \Microsoft\).</summary>
    public static void DeleteTask(string taskPath)
    {
        if (taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Windows tasks are not changed");
        var type = Type.GetTypeFromProgID("Schedule.Service")!;
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        string folder = taskPath[..Math.Max(1, taskPath.LastIndexOf('\\'))];
        string name = taskPath[(taskPath.LastIndexOf('\\') + 1)..];
        service.GetFolder(folder).DeleteTask(name, 0);
        OperationLog.Standard.Write($"task\tdelete\t{taskPath}");
    }

    /// <summary>Removes a Run entry (after a .reg backup) or moves a Startup folder file to the Recycle Bin.</summary>
    public static RemovalOutcome Remove(StartupItem item)
    {
        if (item.Kind == StartupKind.RunKey && item.RegistryKey is not null && item.ValueName is not null)
        {
            var targets = new List<RegistryTarget> { new(item.RegistryKey, item.ValueName) };
            if (item.ApprovedKey is not null)
            {
                using var approved = RegistryCleaner.Open(item.ApprovedKey, writable: false);
                if (approved?.GetValue(item.ValueName) is not null) targets.Add(new RegistryTarget(item.ApprovedKey, item.ValueName));
            }
            return new RegistryCleaner(RemovalMode.Delete, OperationLog.Standard).Remove(targets)[0];
        }
        if (item.Kind == StartupKind.StartupFolder && item.FilePath is { } file)
        {
            var remover = new SafeRemover([Path.GetDirectoryName(file)!], RemovalMode.Recycle, OperationLog.Standard);
            return remover.Remove([file])[0];
        }
        throw new InvalidOperationException("Use the task or service actions");
    }

    /// <summary>Process names of running startup programs, for the "in esecuzione" label.</summary>
    public static HashSet<string> RunningExecutables()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try { if (p.MainModule?.FileName is { } f) result.Add(f); } catch { }
            p.Dispose();
        }
        return result;
    }
}
