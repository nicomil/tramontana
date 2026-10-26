using WinCleaner.Core;

namespace WinCleaner.Modules.Privacy;

public sealed class PrivacyException(string message) : Exception(message);

/// <summary>Cleans privacy items. The owning browser must be closed.</summary>
public static class PrivacyCleaner
{
    /// <summary>Cleans one item (not Wi‑Fi, which goes through the elevated helper).</summary>
    public static void Clean(PrivacyItem item, RemovalMode mode)
    {
        var running = RuleEngine.RunningProcessNames();
        if (item.Processes.FirstOrDefault(running.Contains) is { } process)
            throw new PrivacyException($"Chiudi {item.Owner} ({process}.exe) e riprova: i suoi dati sono in uso");
        if (mode == RemovalMode.DryRun) return;

        switch (item.Action)
        {
            case PrivacyAction.Sql sql:
            {
                // SQL deletions cannot be undone: a copy goes to the Recycle Bin first.
                BackupToRecycleBin(sql.Database, item);
                using var db = SqliteDb.OpenReadWrite(sql.Database) ?? throw new PrivacyException($"Impossibile aprire {Path.GetFileName(sql.Database)}");
                // Browser versions differ: statements on tables this database lacks are skipped.
                var statements = sql.Statements.Where(s => TableOf(s) is not { } table || db.TableExists(table)).ToList();
                if (!db.ExecuteAll(statements)) throw new PrivacyException($"Pulizia di {Path.GetFileName(sql.Database)} non riuscita: nulla è cambiato");
                db.Execute("VACUUM");
                break;
            }
            case PrivacyAction.Files files:
            {
                var roots = files.Paths.Select(Path.GetDirectoryName).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase);
                var remover = new SafeRemover(roots, mode == RemovalMode.Delete ? RemovalMode.Delete : RemovalMode.Recycle, OperationLog.Standard);
                var failed = remover.Remove(files.Paths).Where(o => !o.Succeeded && o.Error != RemovalError.NotFound).ToList();
                if (failed.Count > 0) throw new PrivacyException($"{failed.Count} file non rimossi ({failed[0].Error})");
                break;
            }
            case PrivacyAction.Registry registry:
            {
                var outcomes = new RegistryCleaner(RemovalMode.Delete, OperationLog.Standard).Remove(registry.Targets);
                var failed = outcomes.Where(o => !o.Succeeded && o.Error != RemovalError.NotFound).ToList();
                if (failed.Count > 0) throw new PrivacyException($"{failed.Count} voci del registro non rimosse ({failed[0].Error})");
                break;
            }
            case PrivacyAction.Clipboard:
                ClearClipboard();
                break;
            case PrivacyAction.WiFi:
                throw new PrivacyException("Le reti Wi‑Fi si rimuovono come amministratore");
        }
        OperationLog.Standard.Write($"privacy\tOK {item.Count}\t{item.Id}");
    }

    private static string? TableOf(string statement)
    {
        var parts = statement.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 3 && parts[0].Equals("DELETE", StringComparison.OrdinalIgnoreCase) && parts[1].Equals("FROM", StringComparison.OrdinalIgnoreCase)
            ? parts[2] : null;
    }

    private static void ClearClipboard()
    {
        try
        {
            Windows.ApplicationModel.DataTransfer.Clipboard.ClearHistory();
            Windows.ApplicationModel.DataTransfer.Clipboard.Clear();
        }
        catch (Exception)
        {
            // Without package identity the history API may be unavailable: clear the current content at least.
            if (OpenClipboard(IntPtr.Zero)) { EmptyClipboard(); CloseClipboard(); }
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool OpenClipboard(IntPtr owner);
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool EmptyClipboard();
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool CloseClipboard();

    /// <summary>
    /// Puts a standalone copy of a database in the Recycle Bin, in a folder
    /// such as "WinCleaner, copia di Google Chrome Default History 2026-10-26 10.15.03".
    /// To restore: close the browser, restore the folder and copy the file over the original.
    /// </summary>
    public static string BackupToRecycleBin(string database, PrivacyItem item)
    {
        string stamp = DateTime.Now.ToString("yyyy-MM-dd HH.mm.ss");
        string name = string.Join(" ", new[] { "WinCleaner, copia di", item.Owner, item.Profile, Path.GetFileName(database), stamp }
            .Where(s => !string.IsNullOrEmpty(s)));
        foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '-');
        // Staged on the same drive as the user's Recycle Bin.
        string staging = Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Staging");
        string folder = Path.Combine(staging, name);
        Directory.CreateDirectory(folder);
        string copy = Path.Combine(folder, Path.GetFileName(database));
        using (var source = SqliteDb.OpenReadOnly(database))
        {
            if (source is null || !source.Snapshot(copy))
            {
                TryDelete(folder);
                throw new PrivacyException($"Copia di sicurezza di {Path.GetFileName(database)} non riuscita: nulla è stato cancellato");
            }
        }
        char drive = char.ToUpperInvariant(folder[0]);
        using var bin = RecycleBin.OpenOrCreate(drive);
        if (bin is null)
        {
            TryDelete(folder);
            throw new PrivacyException("Cestino non disponibile: nulla è stato cancellato");
        }
        using var stagingHandle = PinnedFileSystem.OpenDirectoryPath(staging);
        using var handle = PinnedFileSystem.OpenRelative(stagingHandle, name, HandleTree.ItemAccess);
        RecycleBin.Move(bin, drive, handle, folder, HandleTree.Measure(handle));
        return folder;
    }

    private static void TryDelete(string folder)
    {
        try { Directory.Delete(folder, recursive: true); } catch (IOException) { }
    }
}
