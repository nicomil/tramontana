using Tramontana.Modules.Performance;

namespace Tramontana.Modules.Protection;

public enum Severity { Ok, Info, Warning, Danger }

/// <summary>What the app suggests doing about a finding. Nothing happens without the user.</summary>
public enum FindingAction
{
    None,
    /// <summary>Disable the startup entry (StartupApproved, task or service), reversible.</summary>
    DisableStartup,
    /// <summary>Move the file to the Recycle Bin.</summary>
    Recycle,
    /// <summary>Move the file into the app's quarantine.</summary>
    Quarantine,
    /// <summary>Open the Settings page in <see cref="Finding.SettingsLink"/>.</summary>
    OpenSettings,
    /// <summary>Terminate the process (<see cref="Finding.ProcessId"/>).</summary>
    TerminateProcess,
    /// <summary>Delete the registry value in <see cref="Finding.Registry"/> (with a .reg backup, through the helper when needed).</summary>
    RemoveRegistryValue,
    /// <summary>Apply the safe setting the finding describes (reversible, HKCU).</summary>
    FixSetting,
    /// <summary>Scan the file with Microsoft Defender.</summary>
    DefenderScan,
}

/// <summary>The categories the Protection screen groups findings by.</summary>
public static class Categories
{
    public const string Defences = "Difese di Windows";
    public const string Startup = "Avvio automatico";
    public const string Persistence = "Persistenza nascosta";
    public const string Browser = "Browser";
    public const string Network = "Rete";
    public const string Processes = "Processi";
    public const string Programs = "Programmi";
    public const string Configuration = "Configurazione";
    public const string Signatures = "Firme conosciute";
    public const string Devices = "Driver e dispositivi";

    public static readonly string[] Order =
        [Defences, Persistence, Startup, Processes, Programs, Browser, Network, Configuration, Signatures, Devices];
}

/// <summary>One finding of the protection check, always with the reason and the evidence.</summary>
public sealed record Finding(string Id, string Category, string Title, string Reason, Severity Severity)
{
    /// <summary>File or registry place the finding refers to, if any.</summary>
    public string? Path { get; init; }
    /// <summary>Settings page that fixes it (ms-settings: or windowsdefender: link).</summary>
    public string? SettingsLink { get; init; }
    public StartupItem? Startup { get; init; }
    /// <summary>The raw lines the reason is based on: registry values, command lines, permissions.</summary>
    public string[] Evidence { get; init; } = [];
    public FindingAction Action { get; init; }
    /// <summary>Registry key and value an action may remove.</summary>
    public RegistryTargetInfo? Registry { get; init; }
    public int? ProcessId { get; init; }
    /// <summary>Subject of the Authenticode signer, when the finding is about a signed program.</summary>
    public string? Publisher { get; init; }
    /// <summary>When the finding first appeared, according to the saved baseline.</summary>
    public DateTime? FirstSeen { get; init; }
    /// <summary>True when the finding was not in the previous scan.</summary>
    public bool IsNew { get; init; }
}

public sealed record RegistryTargetInfo(string KeyPath, string ValueName);
