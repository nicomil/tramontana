using System.Text.Json;
using System.Text.Json.Serialization;
using WinCleaner.Core;

namespace WinCleaner.Modules.Helper;

/// <summary>The closed set of operations the elevated helper performs.</summary>
public enum HelperOperation
{
    Ping,
    /// <summary>Scan of the system junk rules that need administrator rights.</summary>
    ScanSystemJunk,
    /// <summary>Removal of system files and folders, rechecked by the helper.</summary>
    Remove,
    /// <summary>Deletion of HKEY_LOCAL_MACHINE keys or values (allow list, .reg backup).</summary>
    RemoveRegistry,
    Maintenance,
    /// <summary>Enable or disable an all-users Run or Startup folder entry.</summary>
    SetStartupApproved,
    SetTaskEnabled,
    DeleteTask,
    /// <summary>Start type of a non-Microsoft service: 2 automatic, 3 manual, 4 disabled.</summary>
    SetServiceStart,
    DeleteWiFi,
    /// <summary>Last run times from the Prefetch folder (for "last used").</summary>
    ReadPrefetch,
    /// <summary>Read-only: the root-only facts the Protection checks need (see EvidenceCollection).</summary>
    CollectSystemEvidence,
    /// <summary>Move system files into the system quarantine (Paths, Name = quarantine id).</summary>
    Quarantine,
    /// <summary>Put a system quarantine item back (Name = id, Key = original path).</summary>
    RestoreQuarantined,
    /// <summary>Delete a system quarantine folder (Name = id).</summary>
    DeleteQuarantined,
    /// <summary>Kill a process (Number = pid, Key = expected image path).</summary>
    TerminateProcess,
    /// <summary>Delete or restore one registry value of the Protection allow list (Key, Name).</summary>
    RemoveProtectionValue,
    /// <summary>Remove a Defender exclusion (Name = path, process or extension exactly as listed).</summary>
    RemoveDefenderExclusion,
    /// <summary>Remove a WMI event subscription by consumer name (Name).</summary>
    RemoveWmiSubscription,
    /// <summary>Turn Defender's real-time protection back on.</summary>
    EnableDefenderRealtime,
}

public sealed record HelperRequest
{
    public int Id { get; init; }
    public HelperOperation Operation { get; init; }
    public string[] Paths { get; init; } = [];
    public RemovalMode Mode { get; init; } = RemovalMode.Recycle;
    public RegistryTarget[] Registry { get; init; } = [];
    public string? Name { get; init; }
    public string? Key { get; init; }
    public bool Enabled { get; init; }
    public int Number { get; init; }
    public MaintenanceKind? Task { get; init; }
}

/// <summary>Mirror of <see cref="Performance.MaintenanceTask"/> for the wire (kept separate so the protocol stays stable).</summary>
public enum MaintenanceKind
{
    FlushDns, FreeMemory, WindowsCleanup, ComponentCleanup, SystemFileCheck, RepairImage, DeliveryOptimization, OptimizeDrives, RestorePoint,
}

public sealed record HelperResponse
{
    public int Id { get; init; }
    public bool Ok { get; init; }
    public string? Error { get; init; }
    public string? Text { get; init; }
    public RemovalOutcome[] Outcomes { get; init; } = [];
    public ScanReport? Report { get; init; }
    public Dictionary<string, DateTime>? Times { get; init; }
}

public static class HelperJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}
