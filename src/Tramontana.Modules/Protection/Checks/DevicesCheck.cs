namespace Tramontana.Modules.Protection.Checks;

/// <summary>Devices whose driver reports a problem.</summary>
public sealed class DevicesCheck : IProtectionCheck
{
    public string Id => "devices";
    public string Title => "Driver e dispositivi";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        foreach (var o in context.Wmi.Query(@"root\cimv2", "SELECT Name, DeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0"))
        {
            uint code = Convert.ToUInt32(o.GetValueOrDefault("ConfigManagerErrorCode") ?? 0u);
            if (code is 22 or 45) continue; // disabled by the user, not connected
            string name = o.GetValueOrDefault("Name") as string ?? (o.GetValueOrDefault("DeviceID") as string ?? "Dispositivo");
            string reason = code switch
            {
                28 => "Il driver non è installato.",
                10 => "Il dispositivo non si avvia.",
                43 => "Windows ha fermato il dispositivo perché ha segnalato problemi.",
                _ => $"Gestione dispositivi segnala il codice {code}.",
            };
            yield return new Finding($"device|{o.GetValueOrDefault("DeviceID")}", Categories.Devices, name, reason, Severity.Info)
            { SettingsLink = "ms-settings:windowsupdate-optionalupdates", Action = FindingAction.OpenSettings, Evidence = [$"ConfigManagerErrorCode = {code}"] };
        }
    }
}
