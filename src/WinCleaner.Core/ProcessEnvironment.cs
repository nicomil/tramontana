using System.Diagnostics;

namespace WinCleaner.Core;

/// <summary>
/// A clean environment for the tools WinCleaner starts. The user's environment
/// (HKCU\Environment) reaches even elevated processes, and a few variables let
/// a user-level program run code inside them: the .NET profiler hooks
/// (COR_PROFILER, CORECLR_PROFILER), startup hooks (DOTNET_STARTUP_HOOKS) and
/// the PowerShell module path, whose first entry is a folder in the profile
/// from which cmdlets like Get-MpPreference would be auto-loaded.
/// </summary>
public static class ProcessEnvironment
{
    private static readonly string[] DangerousPrefixes = ["COR_", "CORECLR_", "DOTNET_", "COMPLUS_"];

    /// <summary>Strips the runtime hooks and pins PSModulePath (and, unless told otherwise, PATH) to the Windows folders.</summary>
    public static ProcessStartInfo Sanitize(ProcessStartInfo info, bool restrictPath = true)
    {
        if (info.UseShellExecute) throw new ArgumentException("The environment can only be set when UseShellExecute is false", nameof(info));
        var environment = info.Environment;
        foreach (var key in environment.Keys.ToList())
        {
            if (DangerousPrefixes.Any(p => key.StartsWith(p, StringComparison.OrdinalIgnoreCase))) environment.Remove(key);
        }
        string system32 = Environment.SystemDirectory;
        environment["PSModulePath"] = string.Join(';',
            Path.Combine(system32, "WindowsPowerShell", "v1.0", "Modules"),
            Path.Combine(KnownPaths.ProgramFiles, "WindowsPowerShell", "Modules"));
        if (restrictPath)
            environment["PATH"] = string.Join(';', system32, KnownPaths.Windows, Path.Combine(system32, "Wbem"), Path.Combine(system32, "WindowsPowerShell", "v1.0"));
        return info;
    }

    /// <summary>True when the current process got one of the hooks this class strips: a sign of tampering for an elevated process.</summary>
    public static IReadOnlyList<string> HooksInCurrentProcess()
    {
        var found = new List<string>();
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            string key = entry.Key.ToString() ?? "";
            if (key.Equals("DOTNET_STARTUP_HOOKS", StringComparison.OrdinalIgnoreCase)
                || key.Equals("CORECLR_ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase)
                || key.Equals("CORECLR_PROFILER_PATH", StringComparison.OrdinalIgnoreCase)
                || key.StartsWith("CORECLR_PROFILER_PATH_", StringComparison.OrdinalIgnoreCase)
                || key.Equals("DOTNET_ADDITIONAL_DEPS", StringComparison.OrdinalIgnoreCase)
                || key.Equals("DOTNET_SHARED_STORE", StringComparison.OrdinalIgnoreCase))
                found.Add(key);
        }
        return found;
    }
}
