using System.Text.Json;
using Tramontana.Core;

namespace Tramontana.Modules.Protection.Rules;

/// <summary>
/// The SHA-256 of every rule file and of yara64.exe, confirmed by the user
/// through the elevated helper and kept in a folder only administrators can
/// write (<c>ProgramData\Tramontana\Pins</c>, readable by everyone). A program
/// running with the user's rights can replace the files in the user's Rules
/// folder, but not the pins: the signature scan then refuses to run a changed
/// yara64.exe and skips a changed rule file, saying so.
/// </summary>
public static class RulePins
{
    public static string Folder => Path.Combine(DataFolders.SystemRoot, "Pins");
    public static string File => Path.Combine(Folder, "rules.json");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    /// <summary>name → sha256 (lower case) as pinned, or null when nothing was ever pinned or the file is not trustworthy.</summary>
    public static Dictionary<string, string>? Load(string? file = null)
    {
        file ??= File;
        try
        {
            if (!System.IO.File.Exists(file)) return null;
            SecureFolder.VerifyFile(file);
            var pins = JsonSerializer.Deserialize<Dictionary<string, string>>(System.IO.File.ReadAllText(file), Json);
            return pins is null ? null : new Dictionary<string, string>(pins, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Runs in the helper: hashes the user's rule files and writes the pins into the administrator-only folder.</summary>
    public static int Pin(RuleStore store)
    {
        SecureFolder.Ensure(DataFolders.SystemParent, "Tramontana");
        string folder = SecureFolder.Ensure(DataFolders.SystemParent, ["Tramontana", "Pins"], readableByEveryone: true);
        var pins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in store.Files()) pins[file.Name] = file.Sha256;
        System.IO.File.WriteAllText(Path.Combine(folder, "rules.json"), JsonSerializer.Serialize(pins, Json));
        OperationLog.Standard.Write($"rules\tpin\t{pins.Count}");
        return pins.Count;
    }

    public enum Verdict { Confirmed, Changed, Unconfirmed }

    /// <summary>What the pins say about one file of the store.</summary>
    public static Verdict Check(IReadOnlyDictionary<string, string>? pins, RuleFile file)
    {
        if (pins is null || !pins.TryGetValue(file.Name, out var pinned)) return Verdict.Unconfirmed;
        return string.Equals(pinned, file.Sha256, StringComparison.OrdinalIgnoreCase) ? Verdict.Confirmed : Verdict.Changed;
    }
}
