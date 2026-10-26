using Microsoft.Win32;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// The registry places the Protection checks may fix, each one listed
/// exactly: the general cleaner never touches the Microsoft keys, and this
/// list does not change that. Values that Windows needs are restored to their
/// default instead of deleted. Every change is exported to a .reg file first.
/// </summary>
public static class ProtectionRegistry
{
    /// <summary>Key pattern (with * for one component), value name pattern, and the default to restore (null = delete).</summary>
    private static readonly (string Key, string Value, string? Restore)[] Allowed =
    [
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "*", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe"),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", @"C:\Windows\system32\userinit.exe,"),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Taskman", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AppSetup", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "GinaDLL", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "UIHost", null),
        (@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", null),
        (@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", null),
        (@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Taskman", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*", "DLLName", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*", "Debugger", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*", "MonitorProcess", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", ""),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", ""),
        (@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls", "*", null),
        (@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList", "*", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\*", "StubPath", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\*", "StubPath", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "*", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist", "*", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist", "*", null),
        (@"HKEY_CURRENT_USER\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "*", null),
        (@"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist", "*", null),
        (@"HKEY_CURRENT_USER\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist", "*", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome", "DefaultSearchProviderSearchURL", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome", "HomepageLocation", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome", "NewTabPageLocation", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DefaultSearchProviderSearchURL", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "HomepageLocation", null),
        (@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageLocation", null),
        (@"HKEY_CURRENT_USER\SOFTWARE\Policies\Google\Chrome", "*", null),
        (@"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge", "*", null),
        (@"HKEY_CURRENT_USER\Software\Classes\CLSID\*\TreatAs", "", null),
        (@"HKEY_CURRENT_USER\Software\Classes\CLSID\*\ScriptletURL", "", null),
        (@"HKEY_CURRENT_USER\Software\Classes\CLSID\*\InprocServer32", "", null),
    ];

    /// <summary>The restore value for an allowed target, or null to delete; throws when the target is not in the list.</summary>
    public static string? Resolve(string keyPath, string valueName)
    {
        var key = RegistryCleaner.Normalize(keyPath) ?? throw new InvalidOperationException("chiave non valida");
        foreach (var (pattern, value, restore) in Allowed)
        {
            if (!(value == "*" || value.Equals(valueName, StringComparison.OrdinalIgnoreCase))) continue;
            if (!Matches(key, pattern)) continue;
            return restore;
        }
        throw new InvalidOperationException($"{keyPath} [{valueName}] non è tra le voci che Protezione può modificare");
    }

    public static bool IsAllowed(string keyPath, string valueName)
    {
        try { Resolve(keyPath, valueName); return true; } catch (InvalidOperationException) { return false; }
    }

    internal static bool Matches(string key, string pattern)
    {
        var k = key.Split('\\');
        var p = pattern.Split('\\');
        if (k.Length != p.Length) return false;
        for (int i = 0; i < k.Length; i++)
            if (p[i] != "*" && !k[i].Equals(p[i], StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    public static bool NeedsAdmin(string keyPath) => (RegistryCleaner.Normalize(keyPath) ?? "").StartsWith("HKEY_LOCAL_MACHINE", StringComparison.Ordinal);

    /// <summary>Exports the key, then deletes the value or restores its default. Needs administrator rights for HKLM.</summary>
    public static string Apply(string keyPath, string valueName, OperationLog? log = null)
    {
        string? restore = Resolve(keyPath, valueName);
        string key = RegistryCleaner.Normalize(keyPath)!;
        string backup = Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Backups", "protezione-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".reg");
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        if (!RegistryCleaner.Export(key, backup)) throw new InvalidOperationException("Backup non riuscito: nulla è stato modificato");
        using var opened = RegistryCleaner.Open(key, writable: true) ?? throw new InvalidOperationException("chiave non trovata o non scrivibile");
        if (restore is null) opened.DeleteValue(valueName, throwOnMissingValue: false);
        else opened.SetValue(valueName, restore, RegistryValueKind.String);
        (log ?? OperationLog.Standard).Write($"protection\t{(restore is null ? "delete" : "restore")}\t{key} [{valueName}]\t{backup}");
        return backup;
    }
}
