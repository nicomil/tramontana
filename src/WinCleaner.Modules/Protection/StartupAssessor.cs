using WinCleaner.Core;
using WinCleaner.Modules.Performance;

namespace WinCleaner.Modules.Protection;

/// <summary>
/// The verdict on a program that starts by itself: where it lives, what its
/// command line does, whether it is signed and by whom.
/// </summary>
public static class StartupAssessor
{
    public sealed record Verdict(Severity Severity, string Reason, string[] Evidence, string? Publisher);

    public static Verdict? Assess(StartupItem item, ISignatureEvaluator signatures, string userProfile, HashSet<string>? trustedPublishers = null)
    {
        if (item.IsBroken) return null;
        string? exe = item.Executable;
        if (exe is null) return null;
        string name = Path.GetFileName(exe);
        string command = item.Command ?? "";
        var evidence = new List<string> { $"Comando: {command}" };
        if (item.RegistryKey is not null) evidence.Add($"Chiave: {item.RegistryKey} [{item.ValueName}]");
        if (item.TaskPath is not null) evidence.Add($"Attività: {item.TaskPath}");
        if (item.ServiceName is not null) evidence.Add($"Servizio: {item.ServiceName}");
        if (item.FilePath is not null) evidence.Add($"File: {item.FilePath}");

        var signature = item.Signature ?? signatures.Check(exe);
        if (signature.Status == SignatureStatus.Missing) signature = null;
        string? publisher = signature?.Publisher;
        if (publisher is not null) evidence.Add($"Firmato da: {publisher}");
        else if (signature?.Status == SignatureStatus.Unsigned) evidence.Add("Non firmato");

        var reasons = new List<string>();
        var severity = Severity.Ok;
        void Add(Severity s, string reason) { reasons.Add(reason); if (s > severity) severity = s; }

        if (Suspicion.IsInDangerousFolder(exe, userProfile))
            Add(Severity.Danger, $"Parte da una cartella temporanea o condivisa ({Path.GetDirectoryName(exe)})");

        var commandReasons = Suspicion.CommandLineReasons(command);
        bool scriptHost = Suspicion.ScriptHosts.Contains(name, StringComparer.OrdinalIgnoreCase);
        if (commandReasons.Count > 0)
        {
            foreach (var r in commandReasons) Add(Severity.Danger, r);
        }
        else if (scriptHost)
        {
            Add(Severity.Warning, $"Esegue uno script con {name} all'avvio");
        }

        if (Suspicion.IsBareDataFolder(exe, userProfile))
            Add(Severity.Warning, $"Il programma sta direttamente in {Path.GetDirectoryName(exe)}, dove di solito non ci sono eseguibili");

        if (signature?.Status == SignatureStatus.Invalid)
            Add(Severity.Danger, "La firma digitale del programma non è valida: il file potrebbe essere stato modificato");
        else if (signature?.Status == SignatureStatus.Unsigned && !scriptHost)
        {
            if (Suspicion.IsHiddenFolder(exe)) Add(Severity.Warning, "Programma senza firma digitale in una cartella nascosta");
            else Add(Severity.Info, "Programma senza firma digitale: controlla di conoscerlo");
        }
        if (signature?.Status == SignatureStatus.Signed && signature.IsMicrosoft == false && !string.IsNullOrEmpty(publisher)
            && (item.Name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) || item.Name.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)))
            Add(Severity.Warning, $"Si chiama come un componente di Windows ma è firmato da «{publisher}»");

        if (reasons.Count == 0) return null;
        // A trusted signer silences warnings, never dangers.
        if (publisher is not null && trustedPublishers?.Contains(publisher) == true && severity < Severity.Danger) return null;
        return new Verdict(severity, string.Join(". ", reasons) + ".", [.. evidence], publisher);
    }
}
