using WinCleaner.Core;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// The one privileged, read-only collection: a fixed list of commands, no
/// argument from outside, output split into the sections the checks read.
/// Runs inside the helper.
/// </summary>
public static class EvidenceCollection
{
    public static async Task<string> CollectAsync(CancellationToken cancellation)
    {
        var sb = new System.Text.StringBuilder();
        async Task Section(string name, string file, string[] args)
        {
            sb.Append("### ").Append(name).Append('\n');
            try
            {
                var (_, output) = await Performance.Maintenance.Exec(file, args, cancellation);
                sb.Append(output.Replace("\r\n", "\n")).Append('\n');
            }
            catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException) { sb.Append("(non disponibile: ").Append(e.Message).Append(")\n"); }
        }
        const string ps = "powershell.exe";
        string[] Script(string script) => ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script];

        await Section("defender-exclusions", ps, Script(
            "$p = Get-MpPreference; $p.ExclusionPath | ForEach-Object { 'Path: ' + $_ }; $p.ExclusionProcess | ForEach-Object { 'Process: ' + $_ }; $p.ExclusionExtension | ForEach-Object { 'Extension: ' + $_ }"));
        await Section("bitlocker", "manage-bde.exe", ["-status", KnownPaths.SystemDrive.TrimEnd('\\')]);
        await Section("wmi-subscriptions", ps, Script(
            "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | ForEach-Object { 'filter|' + $_.Name + '|' + $_.Query }; " +
            "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | ForEach-Object { 'consumer|' + $_.Name + '|comando|' + $_.CommandLineTemplate }; " +
            "Get-WmiObject -Namespace root\\subscription -Class ActiveScriptEventConsumer | ForEach-Object { 'consumer|' + $_.Name + '|script ' + $_.ScriptingEngine + '|' + ($_.ScriptText -replace \"`r?`n\", ' ') }; " +
            "Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | ForEach-Object { 'binding|' + ($_.Filter -replace '.*Name=\"(.*)\"', '$1') + '|' + ($_.Consumer -replace '.*Name=\"(.*)\"', '$1') }"));
        await Section("bits", "bitsadmin.exe", ["/list", "/allusers", "/verbose"]);
        await Section("tpm", ps, Script("try { $t = Get-Tpm; 'Present: ' + $t.TpmPresent; 'Ready: ' + $t.TpmReady } catch { 'Present: unknown' }"));
        await Section("processes", ps, Script("Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId.ToString() + '|' + $_.ParentProcessId + '|' + $_.Name + '|' + $_.ExecutablePath + '|' + $_.CommandLine }"));
        await Section("security-log", "wevtutil.exe", ["qe", "Security", "/q:*[System[(EventID=4720 or EventID=4732 or EventID=4698 or EventID=4697 or EventID=1102) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", "/c:50", "/f:text", "/rd:true"]);
        await Section("system-log", "wevtutil.exe", ["qe", "System", "/q:*[System[(EventID=7045 or EventID=104) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", "/c:50", "/f:text", "/rd:true"]);
        return sb.ToString();
    }
}
