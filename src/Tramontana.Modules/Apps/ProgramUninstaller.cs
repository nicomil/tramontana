using System.Diagnostics;
using Tramontana.Core;

namespace Tramontana.Modules.Apps;

public enum UninstallStatus { Removed, StillInstalled, Cancelled, Failed }

public sealed record UninstallResult(UninstallStatus Status, string? Message = null);

/// <summary>
/// Runs a program's own uninstaller (or removes a Store app) and waits for
/// it, including the copies of themselves that many uninstallers start from
/// %TEMP% before exiting.
/// </summary>
public static class ProgramUninstaller
{
    /// <summary>The executable and arguments of the uninstaller, or null when there is none.</summary>
    public static (string File, string Arguments)? Command(InstalledProgram program)
    {
        if (program.ProductCode is { } code) return ("msiexec.exe", $"/x {code}");
        string? command = program.UninstallString ?? program.QuietUninstallString;
        if (string.IsNullOrWhiteSpace(command)) return null;
        command = Environment.ExpandEnvironmentVariables(command.Trim());

        // "MsiExec.exe /I{GUID}" from programs not flagged as Windows Installer.
        var msi = System.Text.RegularExpressions.Regex.Match(command, @"^msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-Fa-f\-]{36}\})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (msi.Success) return ("msiexec.exe", $"/x {msi.Groups[2].Value}");

        // Links such as steam://uninstall/123 are opened by their handler.
        if (System.Text.RegularExpressions.Regex.IsMatch(command, @"^[a-z][a-z0-9+.-]{1,30}://", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            return (command, "");

        string file, arguments;
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end < 0) return null;
            file = command[1..end];
            arguments = command[(end + 1)..].Trim();
        }
        else
        {
            int exe = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exe < 0) return null;
            file = command[..(exe + 4)];
            arguments = command[(exe + 4)..].Trim();
        }
        return File.Exists(file) ? (file, arguments) : null;
    }

    /// <summary>Asks the program's windows to close, then ends what is left after <paramref name="grace"/>.</summary>
    public static async Task CloseRunningAsync(InstalledProgram program, TimeSpan grace, CancellationToken cancellation)
    {
        if (program.InstallLocation is not { } folder) return;
        var processes = InstalledPrograms.ProcessesIn(folder);
        foreach (var p in processes) { try { p.CloseMainWindow(); } catch (InvalidOperationException) { } }
        var deadline = DateTime.UtcNow + grace;
        while (DateTime.UtcNow < deadline && processes.Any(p => { try { return !p.HasExited; } catch { return false; } }))
            await Task.Delay(250, cancellation);
        foreach (var p in processes)
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (Exception) { }
            p.Dispose();
        }
    }

    public static async Task<UninstallResult> RunAsync(InstalledProgram program, CancellationToken cancellation)
    {
        if (program.Source == ProgramSource.Store)
        {
            var error = await StoreApps.RemoveAsync(program.PackageFullName!);
            return error is null ? new UninstallResult(UninstallStatus.Removed) : new UninstallResult(UninstallStatus.Failed, error);
        }

        var command = Command(program);
        if (command is null) return new UninstallResult(UninstallStatus.Failed, "Il programma di disinstallazione non c'è più");

        var started = DateTime.Now;
        Process? process;
        try
        {
            process = Process.Start(new ProcessStartInfo(command.Value.File, command.Value.Arguments) { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            return new UninstallResult(UninstallStatus.Cancelled, "Richiesta di amministratore annullata");
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            return new UninstallResult(UninstallStatus.Failed, e.Message);
        }

        if (process is not null)
        {
            await process.WaitForExitAsync(cancellation);
            process.Dispose();
        }

        // NSIS, Inno Setup and others copy themselves to %TEMP% and run from there.
        while (!cancellation.IsCancellationRequested && HelperUninstallersRunning(started))
            await Task.Delay(1000, cancellation);

        // Some uninstallers remove the registry entry a moment after exiting.
        for (int i = 0; i < 10 && StillRegistered(program); i++) await Task.Delay(500, cancellation);
        return StillRegistered(program)
            ? new UninstallResult(UninstallStatus.StillInstalled, "Il programma risulta ancora installato")
            : new UninstallResult(UninstallStatus.Removed);
    }

    private static readonly string[] UninstallerNames = ["Au_", "Un_A", "Un_B", "unins", "uninst", "_iu14D2N", "uninstall"];

    private static bool HelperUninstallersRunning(DateTime since)
    {
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (!UninstallerNames.Any(n => p.ProcessName.StartsWith(n, StringComparison.OrdinalIgnoreCase))) continue;
                if (p.StartTime >= since.AddSeconds(-2)) return true;
            }
            catch (Exception) { }
            finally { p.Dispose(); }
        }
        return false;
    }

    public static bool StillRegistered(InstalledProgram program)
    {
        if (program.RegistryKey is not { } key) return false;
        using var opened = RegistryCleaner.Open(key, writable: false);
        return opened is not null;
    }
}
