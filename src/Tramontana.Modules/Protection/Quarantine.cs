using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Tramontana.Core;
using static Tramontana.Core.Native.NativeMethods;

namespace Tramontana.Modules.Protection;

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
/// put things back.
///
/// Nothing in the index is trusted: an item is only ever taken from its own
/// folder under the quarantine, put back only inside the allowed roots, and
/// every folder on the way is opened one name at a time without following
/// links. The system quarantine (<see cref="RequireAdminOwner"/>) also checks
/// that the folder and the index belong to administrators, so a user-level
/// program cannot plant a record for the elevated helper to act on.
/// </summary>
public sealed class Quarantine
{
    public string Folder { get; }
    private readonly OperationLog? _log;
    public static string UserFolder => Path.Combine(DataFolders.Root, "Quarantine");
    public static string SystemFolder => Path.Combine(DataFolders.SystemRoot, "Quarantine");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    /// <summary>The folder and the index must be owned by administrators (the helper's quarantine under ProgramData).</summary>
    public bool RequireAdminOwner { get; init; }

    public Quarantine(string? folder = null, OperationLog? log = null)
    {
        Folder = KnownPaths.Long(folder ?? UserFolder);
        _log = log ?? OperationLog.Standard;
    }

    private string Index => Path.Combine(Folder, "index.json");

    /// <summary>The records whose stored folder is really a child of this quarantine; the others are ignored.</summary>
    public List<QuarantineRecord> Records()
    {
        if (RequireAdminOwner) { SecureFolder.Verify(Folder); SecureFolder.VerifyFile(Index); }
        try
        {
            if (File.Exists(Index))
                return (JsonSerializer.Deserialize<List<QuarantineRecord>>(File.ReadAllText(Index), Json) ?? [])
                    .Where(IsWellFormed).OrderByDescending(r => r.Date).ToList();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        return [];
    }

    /// <summary>The stored folder is <see cref="Folder"/>\&lt;id&gt; and the names are plain names.</summary>
    internal bool IsWellFormed(QuarantineRecord record) =>
        PathGuard.IsValidPath(record.StoredFolder)
        && string.Equals(KnownPaths.Long(record.StoredFolder), Path.Combine(Folder, record.Id.ToString("N")), StringComparison.OrdinalIgnoreCase)
        && PathGuard.IsValidName(record.StoredName)
        && PathGuard.IsValidPath(record.OriginalPath)
        && PathGuard.IsValidName(Path.GetFileName(record.OriginalPath));

    private void Save(List<QuarantineRecord> records)
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(Index, JsonSerializer.Serialize(records, Json));
    }

    public void Add(QuarantineRecord record) => Save([.. Records().Where(r => r.Id != record.Id), record]);
    public void Forget(QuarantineRecord record) => Save([.. Records().Where(r => r.Id != record.Id)]);

    private SafeFileHandle OpenRoot(uint access = PinnedFileSystem.DirectoryReadAccess)
    {
        if (RequireAdminOwner) SecureFolder.Verify(Folder);
        return PinnedFileSystem.OpenDirectoryPath(Folder, access, followReparsePoints: false);
    }

    /// <summary>Moves a file or folder inside one of <paramref name="allowedRoots"/> into the quarantine and locks it.</summary>
    public QuarantineRecord Put(string path, string title, string reason, IEnumerable<string> allowedRoots, bool isSystem = false)
    {
        var id = Guid.NewGuid();
        string idName = id.ToString("N");
        string destination = Path.Combine(Folder, idName);
        if (!Directory.Exists(Folder)) Directory.CreateDirectory(Folder);
        using var root = OpenRoot();
        // Created relative to the open root (never by path) so a junction swapped in cannot redirect it.
        using var target = PinnedFileSystem.OpenRelative(root, idName, PinnedFileSystem.DirectoryReadAccess | DELETE, FILE_DIRECTORY_FILE, disposition: FILE_CREATE);
        var remover = new SafeRemover(allowedRoots, RemovalMode.Delete, _log, SafeRemover.DefaultProtectedPaths());
        string name = Path.GetFileName(path);
        var outcome = remover.MoveInto(path, target, name);
        if (outcome.Error is { } error)
        {
            try { PinnedFileSystem.Delete(target); } catch (IOException) { }
            throw new InvalidOperationException($"{path}: {error}{(outcome.Message is null ? "" : " (" + outcome.Message + ")")}");
        }
        Lock(target, name);
        var record = new QuarantineRecord(id, title, KnownPaths.Long(path), reason, DateTime.Now, destination, name, isSystem);
        Add(record);
        _log?.Write($"quarantine\tput\t{record.OriginalPath}\t{record.StoredPath}");
        return record;
    }

    /// <summary>
    /// Puts an item back where it was, provided the place is inside one of
    /// <paramref name="allowedRoots"/>. Missing folders on the way are created
    /// one name at a time; fails if something is there now.
    /// </summary>
    public void Restore(QuarantineRecord record, IEnumerable<string> allowedRoots)
    {
        if (!IsWellFormed(record)) throw new InvalidOperationException("elemento della quarantena non valido");
        string original = KnownPaths.Long(record.OriginalPath);
        string parent = Path.GetDirectoryName(original) ?? throw new InvalidOperationException("percorso non valido");
        string name = Path.GetFileName(original);
        var roots = allowedRoots.Where(PathGuard.IsValidPath).Select(KnownPaths.Long).ToList();
        string allowedRoot = roots.Where(r => PathGuard.IsStrictlyInside(original, r)).OrderByDescending(r => r.Length).FirstOrDefault()
            ?? throw new InvalidOperationException($"{original}: fuori dalle cartelle in cui la quarantena può rimettere i file");
        if (SafeRemover.DefaultProtectedPaths().Any(p => PathGuard.IsSameOrInside(original, KnownPaths.Long(p))))
            throw new InvalidOperationException($"{original}: dentro i dati di Tramontana");

        using var root = OpenRoot();
        Unlock(root, record.Id.ToString("N"));
        using var allowedHandle = PinnedFileSystem.OpenDirectoryPath(allowedRoot);
        string[] components = PathGuard.IsStrictlyInside(parent, allowedRoot) ? PathGuard.RelativeComponents(parent, allowedRoot) : [];
        using var target = PinnedFileSystem.OpenPathCreating(allowedHandle, components);
        try
        {
            using var existing = PinnedFileSystem.OpenRelative(target, name, FILE_READ_ATTRIBUTES);
            throw new InvalidOperationException($"{original}: esiste già qualcosa con questo nome");
        }
        catch (FileSystemException e) when (e.IsNotFound) { }

        var remover = new SafeRemover([Folder], RemovalMode.Delete, _log, []);
        var outcome = remover.MoveInto(record.StoredPath, target, name);
        if (outcome.Error is { } error) throw new InvalidOperationException($"{record.StoredPath}: {error}{(outcome.Message is null ? "" : " (" + outcome.Message + ")")}");
        try { using var folder = PinnedFileSystem.OpenRelative(root, record.Id.ToString("N"), DELETE | FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE); PinnedFileSystem.Delete(folder); }
        catch (IOException) { }
        Forget(record);
        _log?.Write($"quarantine\trestore\t{original}");
    }

    /// <summary>Deletes an item for good.</summary>
    public void Delete(QuarantineRecord record)
    {
        if (!IsWellFormed(record)) throw new InvalidOperationException("elemento della quarantena non valido");
        using (var root = OpenRoot()) Unlock(root, record.Id.ToString("N"));
        var remover = new SafeRemover([Folder], RemovalMode.Delete, _log, []);
        var outcome = remover.Remove([record.StoredFolder]).First();
        if (outcome.Error is { } error && error != RemovalError.NotFound) throw new InvalidOperationException($"{record.StoredFolder}: {error}");
        Forget(record);
        _log?.Write($"quarantine\tdelete\t{record.OriginalPath}");
    }

    // ---- Locking, through handles ----

    private const uint LockAccess = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    private static readonly byte[] ZoneTransfer = Encoding.ASCII.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n");

    /// <summary>Who may still read a locked item: the owner and, for an administrator, the Administrators group.</summary>
    private static List<SecurityIdentifier> Readers()
    {
        var list = new List<SecurityIdentifier> { WindowsIdentity.GetCurrent().User! };
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            list.Add(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return list;
    }

    private static FileSystemSecurity Dacl(bool directory, FileSystemRights rights, bool inherit)
    {
        FileSystemSecurity security = directory ? new DirectorySecurity() : new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        var flags = directory && inherit ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        foreach (var sid in Readers())
            security.AddAccessRule(new FileSystemAccessRule(sid, rights, flags, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    /// <summary>Read, delete and change permissions, plus Synchronize so the handle-based code can open it again; never execute or write.</summary>
    private static readonly FileSystemRights LockedRights = FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.Synchronize;

    /// <summary>Locks the entry <paramref name="name"/> of an open folder: children before parents.</summary>
    internal static void Lock(SafeFileHandle parent, string name)
    {
        try
        {
            using var item = PinnedFileSystem.OpenRelative(parent, name, LockAccess);
            LockTree(item, 0);
        }
        catch (FileSystemException) { }
    }

    private static void LockTree(SafeFileHandle item, int depth)
    {
        HandleInfo info;
        try { info = PinnedFileSystem.GetInfo(item); } catch (FileSystemException) { return; }
        if (info.IsDirectory && !info.IsReparsePoint && depth < 400)
        {
            try
            {
                using var list = PinnedFileSystem.ReOpen(item, PinnedFileSystem.DirectoryReadAccess);
                foreach (var entry in PinnedFileSystem.Enumerate(list))
                {
                    try
                    {
                        using var child = PinnedFileSystem.OpenRelative(list, entry.Name, LockAccess, entry.IsDirectory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
                        LockTree(child, depth + 1);
                    }
                    catch (FileSystemException) { }
                }
            }
            catch (FileSystemException) { }
        }
        else if (!info.IsDirectory && !info.IsReparsePoint)
        {
            // The stream before the Hidden attribute (a hidden file refuses to be overwritten), both before the read-only DACL.
            try
            {
                PinnedFileSystem.SetAttributes(item, info.Attributes & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN));
                try
                {
                    using var zone = PinnedFileSystem.OpenStream(item, "Zone.Identifier", FILE_WRITE_DATA, FILE_OVERWRITE_IF);
                    RandomAccess.Write(zone, ZoneTransfer, 0);
                }
                catch (FileSystemException) { }
                PinnedFileSystem.SetAttributes(item, (info.Attributes & ~FILE_ATTRIBUTE_READONLY) | FILE_ATTRIBUTE_HIDDEN);
            }
            catch (FileSystemException) { }
        }
        try { PinnedFileSystem.SetDacl(item, Dacl(info.IsDirectory, LockedRights, inherit: false)); } catch (FileSystemException) { }
    }

    /// <summary>Unlocks the entry <paramref name="name"/> of an open folder: parents first, so their children can be opened again.</summary>
    internal static void Unlock(SafeFileHandle parent, string name)
    {
        try
        {
            using var item = PinnedFileSystem.OpenRelative(parent, name, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES);
            UnlockTree(item, 0);
        }
        catch (FileSystemException) { }
    }

    private static void UnlockTree(SafeFileHandle item, int depth)
    {
        HandleInfo info;
        try { info = PinnedFileSystem.GetInfo(item); } catch (FileSystemException) { return; }
        try { PinnedFileSystem.SetDacl(item, Dacl(info.IsDirectory, FileSystemRights.FullControl, inherit: true)); } catch (FileSystemException) { }
        if (info.IsDirectory && !info.IsReparsePoint && depth < 400)
        {
            try
            {
                using var list = PinnedFileSystem.ReOpen(item, PinnedFileSystem.DirectoryReadAccess);
                foreach (var entry in PinnedFileSystem.Enumerate(list))
                {
                    try
                    {
                        using var child = PinnedFileSystem.OpenRelative(list, entry.Name, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, entry.IsDirectory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE);
                        UnlockTree(child, depth + 1);
                    }
                    catch (FileSystemException) { }
                }
            }
            catch (FileSystemException) { }
        }
        else if (!info.IsDirectory && !info.IsReparsePoint)
        {
            try
            {
                using var writable = PinnedFileSystem.ReOpen(item, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES);
                PinnedFileSystem.SetAttributes(writable, info.Attributes & ~FILE_ATTRIBUTE_HIDDEN);
                try
                {
                    using var zone = PinnedFileSystem.OpenStream(writable, "Zone.Identifier", DELETE, FILE_OPEN);
                    PinnedFileSystem.Delete(zone);
                }
                catch (FileSystemException) { }
            }
            catch (FileSystemException) { }
        }
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
