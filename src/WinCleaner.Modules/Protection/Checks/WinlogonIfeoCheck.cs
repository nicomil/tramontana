using WinCleaner.Core;
using WinCleaner.Modules.Performance;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// The persistence spots that run before or instead of the normal shell:
/// Winlogon (Shell, Userinit), Image File Execution Options (a "debugger"
/// that replaces a program, the sticky-keys backdoor), AppInit and AppCert
/// DLLs loaded into every process, and the accessibility tools themselves.
/// </summary>
public sealed class WinlogonIfeoCheck : IProtectionCheck
{
    public string Id => "winlogon-ifeo";
    public string Title => "Winlogon, IFEO e DLL iniettate";

    private const string WinlogonMachine = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string WinlogonUser = @"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Ifeo = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SilentExit = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
    private static readonly string[] AccessibilityTools = ["sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();

        // Winlogon: Shell must be explorer.exe, Userinit must be userinit.exe.
        foreach (var (key, scope) in new[] { (WinlogonMachine, "tutti gli utenti"), (WinlogonUser, "questo utente") })
        {
            var shell = r.GetString(key, "Shell");
            if (shell is not null && !IsOnly(shell, "explorer.exe"))
                list.Add(Danger($"winlogon|shell|{scope}", "Shell di Windows sostituita o affiancata",
                    $"All'accesso parte «{shell}» invece del solo explorer.exe ({scope}): tutto ciò che c'è dopo la virgola è un programma estraneo.", key, "Shell", shell, context, scope == "tutti gli utenti"));
            var userinit = r.GetString(key, "Userinit");
            if (userinit is not null && !IsOnly(userinit, "userinit.exe"))
                list.Add(Danger($"winlogon|userinit|{scope}", "Userinit modificato",
                    $"Prima del desktop parte «{userinit}» ({scope}): il valore normale è solo userinit.exe.", key, "Userinit", userinit, context, scope == "tutti gli utenti"));
            foreach (var value in new[] { "Taskman", "VmApplet", "AppSetup", "GinaDLL", "UIHost" })
                if (r.GetString(key, value) is { Length: > 0 } extra && !(value == "VmApplet" && extra.Contains("SystemPropertiesPerformance", StringComparison.OrdinalIgnoreCase)))
                    list.Add(Danger($"winlogon|{value}|{scope}", $"Winlogon {value} impostato", $"Un programma extra viene avviato da Winlogon tramite «{value}» ({scope}).", key, value, extra, context, scope == "tutti gli utenti"));
        }
        foreach (var sub in r.SubKeys(WinlogonMachine + @"\Notify"))
        {
            var dll = r.GetString($@"{WinlogonMachine}\Notify\{sub}", "DLLName");
            if (dll is not null)
                list.Add(Danger($"winlogon|notify|{sub}", $"Pacchetto di notifica Winlogon: {sub}", "Una DLL viene caricata a ogni accesso (tecnica non più usata da programmi legittimi).", $@"{WinlogonMachine}\Notify\{sub}", "DLLName", dll, context, true));
        }

        // IFEO: a Debugger value runs another program in place of the named one.
        foreach (var exe in r.SubKeys(Ifeo))
        {
            var debugger = r.GetString($@"{Ifeo}\{exe}", "Debugger");
            if (debugger is null) continue;
            bool accessibility = AccessibilityTools.Contains(exe, StringComparer.OrdinalIgnoreCase);
            // Developers sometimes attach vsjitdebugger: still worth a look, but not a backdoor.
            bool devTool = debugger.Contains("vsjitdebugger", StringComparison.OrdinalIgnoreCase) || debugger.Contains("windbg", StringComparison.OrdinalIgnoreCase);
            list.Add(new Finding($"ifeo|{exe}", Categories.Persistence,
                accessibility ? $"Porta di servizio nella schermata di blocco: {exe}" : $"Un altro programma sostituisce {exe}",
                accessibility ? $"Premendo 5 volte Maiusc (o il pulsante Accessibilità) nella schermata di accesso parte «{debugger}» con i diritti di SYSTEM, senza password."
                              : $"Ogni volta che qualcuno apre {exe} viene eseguito «{debugger}» al suo posto.",
                devTool ? Severity.Info : Severity.Danger)
            { Path = $@"{Ifeo}\{exe}", Evidence = [$@"{Ifeo}\{exe} [Debugger] = {debugger}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo($@"{Ifeo}\{exe}", "Debugger") });
        }
        foreach (var exe in r.SubKeys(SilentExit))
        {
            var monitor = r.GetString($@"{SilentExit}\{exe}", "MonitorProcess");
            if (monitor is null) continue;
            list.Add(new Finding($"silentexit|{exe}", Categories.Persistence, $"Un programma parte quando {exe} si chiude",
                $"SilentProcessExit avvia «{monitor}» alla chiusura di {exe}: tecnica di persistenza poco nota.", Severity.Danger)
            { Path = $@"{SilentExit}\{exe}", Evidence = [$@"{SilentExit}\{exe} [MonitorProcess] = {monitor}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo($@"{SilentExit}\{exe}", "MonitorProcess") });
        }

        // AppInit_DLLs: loaded into every process that uses user32.
        foreach (var key in new[] { @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
        {
            var dlls = r.GetString(key, "AppInit_DLLs");
            if (string.IsNullOrWhiteSpace(dlls)) continue;
            bool loaded = (r.GetInt(key, "LoadAppInit_DLLs") ?? 0) == 1;
            list.Add(new Finding($"appinit|{key.Contains("WOW6432Node")}", Categories.Persistence, loaded ? "DLL iniettata in ogni programma (AppInit_DLLs)" : "AppInit_DLLs impostato (non attivo)",
                loaded ? $"«{dlls}» viene caricata in ogni finestra aperta: può leggere tutto ciò che fai." : $"«{dlls}» è pronta per essere caricata in ogni programma appena LoadAppInit_DLLs passa a 1.",
                loaded ? Severity.Danger : Severity.Warning)
            { Path = key, Evidence = [$"{key} [AppInit_DLLs] = {dlls}", $"LoadAppInit_DLLs = {(loaded ? 1 : 0)}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo(key, "AppInit_DLLs") });
        }
        const string appCert = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
        foreach (var name in r.ValueNames(appCert))
            if (r.GetString(appCert, name) is { } dll)
                list.Add(new Finding($"appcert|{name}", Categories.Persistence, $"DLL AppCert: {name}", $"«{dll}» viene consultata a ogni avvio di un programma.", Severity.Danger)
                { Path = appCert, Evidence = [$"{appCert} [{name}] = {dll}"], Action = FindingAction.RemoveRegistryValue, Registry = new RegistryTargetInfo(appCert, name) });

        // The accessibility tools themselves, replaced on disk.
        foreach (var tool in AccessibilityTools)
        {
            string path = Path.Combine(Environment.SystemDirectory, tool);
            var signature = context.Signatures.Check(path);
            if (signature.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid || (signature.Status == SignatureStatus.Signed && signature.IsMicrosoft == false))
                list.Add(new Finding($"accessibility-binary|{tool}", Categories.Persistence, $"{tool} non è quello di Windows",
                    "Il file dello strumento di accessibilità è stato sostituito: dalla schermata di accesso aprirebbe quel programma come SYSTEM.", Severity.Danger)
                { Path = path, Evidence = [$"{path}: firma {signature.Status}{(signature.Publisher is null ? "" : " di " + signature.Publisher)}"], Action = FindingAction.DefenderScan });
        }
        return list;
    }

    private static bool IsOnly(string value, string expected)
    {
        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 1 && (parts[0].Equals(expected, StringComparison.OrdinalIgnoreCase)
            || parts[0].EndsWith("\\" + expected, StringComparison.OrdinalIgnoreCase));
    }

    private static Finding Danger(string id, string title, string reason, string key, string value, string raw, CheckContext context, bool machine)
    {
        // Point at the extra program when there is one.
        string? extra = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => StartupManager.ExecutableOf(p)).FirstOrDefault(p => p is not null && !Suspicion.IsInWindows(p));
        return new Finding(id, Categories.Persistence, title, reason, Severity.Danger)
        {
            Path = extra ?? key,
            Evidence = [$"{key} [{value}] = {raw}"],
            Action = FindingAction.RemoveRegistryValue,
            Registry = new RegistryTargetInfo(key, value),
        };
    }
}
