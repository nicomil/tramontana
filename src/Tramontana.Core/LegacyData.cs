namespace Tramontana.Core;

/// <summary>
/// Carries over what the app kept under its previous name, WinCleaner (up to
/// version 0.2): settings, operation log, registry backups, quarantine, rules and
/// pins. A folder is moved only when the new one does not exist yet, so a user who
/// already started Tramontana keeps what it has; the old folder is then left alone.
/// Moving keeps the files' permissions, which matters for the administrator-only
/// folder under ProgramData.
/// </summary>
public static class LegacyData
{
    public const string OldName = "WinCleaner";

    /// <summary>%LOCALAPPDATA%\WinCleaner → %LOCALAPPDATA%\Tramontana. Returns a sentence for the log, or null when there was nothing to do.</summary>
    public static string? MigrateUser() => MigrateUser(Path.Combine(KnownPaths.LocalAppData, OldName), DataFolders.UserRoot);

    internal static string? MigrateUser(string old, string current)
    {
        if (!Directory.Exists(old)) return null;
        try
        {
            if (Directory.Exists(current))
            {
                // Both exist: only the settings are worth taking, and only if the new app has none yet.
                string oldSettings = Path.Combine(old, "settings.json"), newSettings = Path.Combine(current, "settings.json");
                if (File.Exists(oldSettings) && !File.Exists(newSettings)) { File.Copy(oldSettings, newSettings); return $"impostazioni copiate da {old}"; }
                return null;
            }
            return Move(old, current);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return $"cartella {old} non spostata: {e.Message}";
        }
    }

    /// <summary>
    /// ProgramData\WinCleaner → ProgramData\Tramontana, from the elevated helper. The old
    /// folder is adopted only if it still has the layout the helper created it with
    /// (administrators own it, nobody else writes to it, no junction): anything else stays
    /// where it is, so a planted folder cannot become the helper's data folder.
    /// </summary>
    public static string? MigrateSystem() => MigrateSystem(Path.Combine(DataFolders.SystemParent, OldName), DataFolders.SystemRoot);

    internal static string? MigrateSystem(string old, string current)
    {
        if (!Directory.Exists(old) || Directory.Exists(current)) return null;
        try
        {
            SecureFolder.Verify(old);
            return Move(old, current);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return $"cartella {old} non spostata: {e.Message}";
        }
    }

    private static string Move(string old, string current)
    {
        // A link in place of the old folder is not ours to move.
        if (File.GetAttributes(old).HasFlag(FileAttributes.ReparsePoint)) throw new IOException("la cartella è un collegamento");
        Directory.Move(old, current);
        RewriteQuarantineIndex(Path.Combine(current, "Quarantine", "index.json"), old, current);
        return $"dati spostati da {old} a {current}";
    }

    /// <summary>
    /// The quarantine index stores the absolute folder of each item, and an item whose
    /// folder is not under the quarantine is ignored on purpose: after the move the old
    /// root is replaced by the new one, in the JSON-escaped form the serializer writes.
    /// </summary>
    private static void RewriteQuarantineIndex(string index, string oldRoot, string newRoot)
    {
        if (!File.Exists(index)) return;
        string text = File.ReadAllText(index);
        string from = oldRoot.Replace("\\", "\\\\"), to = newRoot.Replace("\\", "\\\\");
        string updated = text.Replace(from + "\\\\", to + "\\\\", StringComparison.OrdinalIgnoreCase);
        if (updated != text) File.WriteAllText(index, updated);
    }
}
