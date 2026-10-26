using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using WinCleaner.Core;

namespace WinCleaner.Modules.Protection;

/// <summary>One item put aside by the user: where it was, why, and where it is now.</summary>
public sealed record QuarantineRecord(Guid Id, string Title, string OriginalPath, string Reason, DateTime Date, string StoredFolder, string StoredName, bool IsSystem)
{
    public string StoredPath => Path.Combine(StoredFolder, StoredName);
}

/// <summary>
/// Where dangerous items go instead of the Recycle Bin: one folder per item,
/// moved through its handle (never by path), with a DACL that lets only the
/// owner read it, the Hidden attribute, and a Zone.Identifier stream so
/// SmartScreen would stop even a copy. The index keeps what the user needs to
/// put things back. System items live in a ProgramData folder the helper owns.
/// </summary>
public sealed class Quarantine
{
    public string Folder { get; }
    private readonly OperationLog? _log;
    public static string UserFolder => Path.Combine(KnownPaths.LocalAppData, "WinCleaner", "Quarantine");
    public static string SystemFolder => Path.Combine(KnownPaths.ProgramData, "WinCleaner", "Quarantine");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public Quarantine(string? folder = null, OperationLog? log = null)
    {
        Folder = folder ?? UserFolder;
        _log = log ?? OperationLog.Standard;
    }

    private string Index => Path.Combine(Folder, "index.json");

    public List<QuarantineRecord> Records()
    {
        try
        {
            if (File.Exists(Index)) return (JsonSerializer.Deserialize<List<QuarantineRecord>>(File.ReadAllText(Index), Json) ?? []).OrderByDescending(r => r.Date).ToList();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        return [];
    }

    private void Save(List<QuarantineRecord> records)
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(Index, JsonSerializer.Serialize(records, Json));
    }

    public void Add(QuarantineRecord record) => Save([.. Records().Where(r => r.Id != record.Id), record]);
    public void Forget(QuarantineRecord record) => Save([.. Records().Where(r => r.Id != record.Id)]);

    /// <summary>Moves a file or folder inside one of <paramref name="allowedRoots"/> into the quarantine and locks it.</summary>
    public QuarantineRecord Put(string path, string title, string reason, IEnumerable<string> allowedRoots, bool isSystem = false)
    {
        var id = Guid.NewGuid();
        string destination = Path.Combine(Folder, id.ToString("N"));
        Directory.CreateDirectory(destination);
        var remover = new SafeRemover(allowedRoots, RemovalMode.Delete, _log, SafeRemover.DefaultProtectedPaths());
        using var target = PinnedFileSystem.OpenDirectoryPath(destination);
        string name = Path.GetFileName(path);
        var outcome = remover.MoveInto(path, target, name);
        if (outcome.Error is { } error)
        {
            try { Directory.Delete(destination); } catch (IOException) { }
            throw new InvalidOperationException($"{path}: {error}{(outcome.Message is null ? "" : " (" + outcome.Message + ")")}");
        }
        Lock(Path.Combine(destination, name));
        var record = new QuarantineRecord(id, title, KnownPaths.Long(path), reason, DateTime.Now, destination, name, isSystem);
        Add(record);
        _log?.Write($"quarantine\tput\t{record.OriginalPath}\t{record.StoredPath}");
        return record;
    }

    /// <summary>Puts a user item back where it was. Fails if something is there now.</summary>
    public void Restore(QuarantineRecord record)
    {
        string parent = Path.GetDirectoryName(record.OriginalPath) ?? throw new InvalidOperationException("percorso non valido");
        Directory.CreateDirectory(parent);
        if (File.Exists(record.OriginalPath) || Directory.Exists(record.OriginalPath)) throw new InvalidOperationException($"{record.OriginalPath}: esiste già qualcosa con questo nome");
        Unlock(record.StoredPath);
        var remover = new SafeRemover([record.StoredFolder], RemovalMode.Delete, _log, []);
        using var target = PinnedFileSystem.OpenDirectoryPath(parent);
        var outcome = remover.MoveInto(record.StoredPath, target, Path.GetFileName(record.OriginalPath));
        if (outcome.Error is { } error) throw new InvalidOperationException($"{record.StoredPath}: {error}{(outcome.Message is null ? "" : " (" + outcome.Message + ")")}");
        try { Directory.Delete(record.StoredFolder); } catch (IOException) { }
        Forget(record);
        _log?.Write($"quarantine\trestore\t{record.OriginalPath}");
    }

    /// <summary>Deletes an item for good.</summary>
    public void Delete(QuarantineRecord record)
    {
        Unlock(record.StoredPath);
        var remover = new SafeRemover([Folder], RemovalMode.Delete, _log, []);
        var outcome = remover.Remove([record.StoredFolder]).First();
        if (outcome.Error is { } error && error != RemovalError.NotFound) throw new InvalidOperationException($"{record.StoredFolder}: {error}");
        Forget(record);
        _log?.Write($"quarantine\tdelete\t{record.OriginalPath}");
    }

    /// <summary>Owner may read, nobody may execute; hidden; marked as downloaded from the internet.</summary>
    public static void Lock(string path)
    {
        var owner = WindowsIdentity.GetCurrent().User!;
        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        var rules = new List<FileSystemAccessRule> { new(owner, FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.ChangePermissions, AccessControlType.Allow) };
        if (admin) rules.Add(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.ChangePermissions, AccessControlType.Allow));
        // Children before parents: a folder locked first would block the work on its files.
        foreach (var file in Enumerable.Reverse(Walk(path)))
        {
            try
            {
                if (Directory.Exists(file))
                {
                    var security = new DirectorySecurity();
                    security.SetAccessRuleProtection(true, false);
                    foreach (var rule in rules) security.AddAccessRule(new FileSystemAccessRule(rule.IdentityReference, rule.FileSystemRights, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                    new DirectoryInfo(file).SetAccessControl(security);
                }
                else
                {
                    // The stream before the Hidden attribute (a hidden file refuses new streams), both before the read-only DACL.
                    File.SetAttributes(file, File.GetAttributes(file) & ~(FileAttributes.ReadOnly | FileAttributes.Hidden));
                    try
                    {
                        using var stream = new FileStream(file + ":Zone.Identifier", FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
                        stream.SetLength(0);
                        using var writer = new StreamWriter(stream);
                        writer.Write("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n");
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                    File.SetAttributes(file, File.GetAttributes(file) | FileAttributes.Hidden);
                    var security = new FileSecurity();
                    security.SetAccessRuleProtection(true, false);
                    foreach (var rule in rules) security.AddAccessRule(rule);
                    new FileInfo(file).SetAccessControl(security);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    public static void Unlock(string path)
    {
        var owner = WindowsIdentity.GetCurrent().User!;
        // Parents first: the folder must open again before its files can be touched.
        foreach (var file in Walk(path))
        {
            try
            {
                if (Directory.Exists(file))
                {
                    var security = new DirectorySecurity();
                    security.SetAccessRuleProtection(true, false);
                    security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    new DirectoryInfo(file).SetAccessControl(security);
                }
                else
                {
                    var security = new FileSecurity();
                    security.SetAccessRuleProtection(true, false);
                    security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
                    new FileInfo(file).SetAccessControl(security);
                    File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Hidden);
                    try { File.Delete(file + ":Zone.Identifier"); } catch (IOException) { }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>The item and everything below it, parents first; links are listed, never followed.</summary>
    private static List<string> Walk(string path)
    {
        var list = new List<string> { path };
        if (!Directory.Exists(path) || new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint)) return list;
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
                list.Add(entry);
        }
        catch (IOException) { }
        return list;
    }

    /// <summary>The user roots a quarantine may take from: the profile, including its hidden folders, and ProgramData's program folders.</summary>
    public static IReadOnlyList<string> UserRoots()
    {
        var roots = new List<string> { KnownPaths.LocalAppData, KnownPaths.RoamingAppData, KnownPaths.LocalAppDataLow, KnownPaths.Temp, KnownPaths.Public, KnownPaths.Downloads, KnownPaths.Desktop, KnownPaths.Documents };
        try
        {
            foreach (var dir in new DirectoryInfo(KnownPaths.UserProfile).EnumerateDirectories())
                if (!roots.Contains(dir.FullName, StringComparer.OrdinalIgnoreCase) && !dir.Name.Equals("AppData", StringComparison.OrdinalIgnoreCase)) roots.Add(dir.FullName);
        }
        catch (IOException) { }
        return roots;
    }
}
