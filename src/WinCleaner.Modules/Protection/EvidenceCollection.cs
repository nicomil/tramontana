using System.Management;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// The one privileged, read-only collection: WMI queries and a fixed list of
/// commands, no argument from outside, output split into the sections the
/// checks read. Runs inside the helper. PowerShell is not used: an elevated
/// PowerShell auto-loads modules from the user's profile and honours the
/// user's .NET Framework profiler variables, both of which a user-level
/// program can plant.
/// </summary>
public static class EvidenceCollection
{
    public static async Task<string> CollectAsync(CancellationToken cancellation)
    {
        var sb = new System.Text.StringBuilder();
        void Section(string name, Func<IEnumerable<string>> lines)
        {
            sb.Append("### ").Append(name).Append('\n');
            try
            {
                foreach (var line in lines()) sb.Append(line.Replace("\r\n", " ").Replace('\n', ' ')).Append('\n');
            }
            catch (Exception e) when (e is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException)
            { sb.Append("(non disponibile: ").Append(e.Message).Append(")\n"); }
        }
        async Task Command(string name, string file, string[] args)
        {
            sb.Append("### ").Append(name).Append('\n');
            try
            {
                var (_, output) = await Performance.Maintenance.Exec(file, args, cancellation);
                sb.Append(output.Replace("\r\n", "\n")).Append('\n');
            }
            catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException) { sb.Append("(non disponibile: ").Append(e.Message).Append(")\n"); }
        }

        Section("defender-exclusions", DefenderExclusions);
        await Command("bitlocker", "manage-bde.exe", ["-status", KnownPaths.SystemDrive.TrimEnd('\\')]);
        Section("wmi-subscriptions", WmiSubscriptions);
        await Command("bits", "bitsadmin.exe", ["/list", "/allusers", "/verbose"]);
        Section("tpm", Tpm);
        Section("processes", Processes);
        await Command("security-log", "wevtutil.exe", ["qe", "Security", "/q:*[System[(EventID=4720 or EventID=4732 or EventID=4698 or EventID=4697 or EventID=1102) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", "/c:50", "/f:text", "/rd:true"]);
        await Command("system-log", "wevtutil.exe", ["qe", "System", "/q:*[System[(EventID=7045 or EventID=104) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", "/c:50", "/f:text", "/rd:true"]);
        return sb.ToString();
    }

    private static IEnumerable<Dictionary<string, object?>> Query(string scope, string wql) => new SystemWmi().Query(scope, wql);

    private static string[] Strings(object? value) => value switch { string[] a => a, string s when s.Length > 0 => [s], _ => [] };

    /// <summary>"Path: x", "Process: x", "Extension: x" (the standard user cannot read them on recent builds).</summary>
    private static IEnumerable<string> DefenderExclusions()
    {
        var preferences = Query(@"root\Microsoft\Windows\Defender", "SELECT ExclusionPath, ExclusionProcess, ExclusionExtension FROM MSFT_MpPreference").FirstOrDefault();
        if (preferences is null) yield break;
        foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionPath"))) yield return "Path: " + p;
        foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionProcess"))) yield return "Process: " + p;
        foreach (var p in Strings(preferences.GetValueOrDefault("ExclusionExtension"))) yield return "Extension: " + p;
    }

    /// <summary>filter|name|query, consumer|name|kind|command, binding|filter|consumer (the format WmiBitsCheck reads).</summary>
    private static IEnumerable<string> WmiSubscriptions()
    {
        const string scope = @"root\subscription";
        foreach (var f in Query(scope, "SELECT Name, Query FROM __EventFilter"))
            yield return $"filter|{f.GetValueOrDefault("Name")}|{f.GetValueOrDefault("Query")}";
        foreach (var c in Query(scope, "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer"))
            yield return $"consumer|{c.GetValueOrDefault("Name")}|comando|{c.GetValueOrDefault("CommandLineTemplate") ?? c.GetValueOrDefault("ExecutablePath")}";
        foreach (var c in Query(scope, "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer"))
            yield return $"consumer|{c.GetValueOrDefault("Name")}|script {c.GetValueOrDefault("ScriptingEngine")}|{c.GetValueOrDefault("ScriptText") ?? c.GetValueOrDefault("ScriptFileName")}";
        foreach (var b in Query(scope, "SELECT Filter, Consumer FROM __FilterToConsumerBinding"))
            yield return $"binding|{RefName(b.GetValueOrDefault("Filter"))}|{RefName(b.GetValueOrDefault("Consumer"))}";
    }

    /// <summary>"__EventFilter.Name=\"X\"" → X.</summary>
    internal static string RefName(object? reference)
    {
        var s = reference as string ?? "";
        int eq = s.IndexOf('=');
        return eq < 0 ? s : s[(eq + 1)..].Trim('"');
    }

    private static IEnumerable<string> Tpm()
    {
        var tpm = Query(@"root\cimv2\Security\MicrosoftTpm", "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue FROM Win32_Tpm").FirstOrDefault();
        if (tpm is null) { yield return "Present: False"; yield return "Ready: False"; yield break; }
        bool ready = tpm.GetValueOrDefault("IsEnabled_InitialValue") is true && tpm.GetValueOrDefault("IsActivated_InitialValue") is true && tpm.GetValueOrDefault("IsOwned_InitialValue") is true;
        yield return "Present: True";
        yield return "Ready: " + ready;
    }

    /// <summary>pid|ppid|name|path|command line, every process of every user.</summary>
    private static IEnumerable<string> Processes()
    {
        foreach (var p in Query(@"root\cimv2", "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process"))
            yield return $"{p.GetValueOrDefault("ProcessId")}|{p.GetValueOrDefault("ParentProcessId")}|{p.GetValueOrDefault("Name")}|{p.GetValueOrDefault("ExecutablePath")}|{p.GetValueOrDefault("CommandLine")}";
    }
}
