using System.Security.AccessControl;
using System.Security.Principal;

namespace WinCleaner.Core;

/// <summary>
/// Folders that only administrators may change. The elevated helper keeps its
/// quarantine, log and backups here: each folder is created with an explicit
/// DACL (Administrators and SYSTEM only, no inheritance from ProgramData) and
/// checked before every use, so a user-level process that got there first
/// cannot plant a folder, a file or a junction the helper would then trust.
/// </summary>
public static class SecureFolder
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new(KnownSids.TrustedInstaller);

    /// <summary>Owners a trusted folder or file may have.</summary>
    private static bool IsTrustedOwner(IdentityReference? owner) =>
        owner is SecurityIdentifier sid && (sid == Administrators || sid == LocalSystem || sid == TrustedInstaller);

    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    /// <summary>The DACL of a helper folder: Administrators and SYSTEM full control, inherited by everything below; optionally read for Users.</summary>
    public static DirectorySecurity AdminOnly(bool readableByEveryone = false)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { Administrators, LocalSystem })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (readableByEveryone)
            security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// Returns <paramref name="trustedRoot"/>\<paramref name="components"/>, creating every missing
    /// component as an administrator-only folder and checking every existing one: not a reparse
    /// point, owned by Administrators or SYSTEM, and with a DACL that lets nobody else in (a
    /// folder of ours with a looser DACL, for example one created by an older version, is
    /// tightened). Throws <see cref="UnauthorizedAccessException"/> when a component fails.
    /// </summary>
    public static string Ensure(string trustedRoot, params string[] components) => Ensure(trustedRoot, components, readableByEveryone: false);

    /// <summary>As <see cref="Ensure(string, string[])"/>; with <paramref name="readableByEveryone"/> the last folder may be read (never written) by Users.</summary>
    public static string Ensure(string trustedRoot, string[] components, bool readableByEveryone)
    {
        if (!PathGuard.IsValidPath(trustedRoot)) throw new ArgumentException("Cartella radice non valida", nameof(trustedRoot));
        string current = KnownPaths.Long(trustedRoot);
        for (int i = 0; i < components.Length; i++)
        {
            string component = components[i];
            bool readers = readableByEveryone && i == components.Length - 1;
            if (!PathGuard.IsValidName(component)) throw new ArgumentException($"Nome non valido: {component}", nameof(components));
            current = Path.Combine(current, component);
            if (!Directory.Exists(current) && !File.Exists(current))
            {
                // A user that creates the folder between this check and the creation becomes its
                // owner: the verification below notices and refuses.
                try { AdminOnly(readers).CreateDirectory(current); }
                catch (IOException) { }
            }
            Verify(current, readers);
        }
        return current;
    }

    /// <summary>Checks one folder (see <see cref="Ensure"/>), tightening a DACL of ours that is too loose.</summary>
    public static void Verify(string folder) => Verify(folder, allowReaders: false);

    public static void Verify(string folder, bool allowReaders)
    {
        var info = new DirectoryInfo(folder);
        if (!info.Exists) throw new UnauthorizedAccessException($"{folder}: non è una cartella");
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException($"{folder}: è un collegamento, non una cartella");
        DirectorySecurity security;
        try { security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.Principal.IdentityNotMappedException)
        { throw new UnauthorizedAccessException($"{folder}: permessi non leggibili ({e.Message})"); }
        if (!IsTrustedOwner(security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException($"{folder}: non appartiene agli amministratori. Rimuovi la cartella e riprova.");
        if (!IsStrict(security, allowReaders))
        {
            try { info.SetAccessControl(AdminOnly(allowReaders)); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            { throw new UnauthorizedAccessException($"{folder}: impossibile limitarla agli amministratori ({e.Message})"); }
            if (!IsStrict(info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), allowReaders))
                throw new UnauthorizedAccessException($"{folder}: i permessi restano troppo larghi");
        }
    }

    /// <summary>A file inside a trusted folder: not a reparse point and owned by administrators.</summary>
    public static void VerifyFile(string file)
    {
        var info = new FileInfo(file);
        if (!info.Exists) return;
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new UnauthorizedAccessException($"{file}: è un collegamento");
        FileSecurity security;
        try { security = info.GetAccessControl(AccessControlSections.Owner); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.Principal.IdentityNotMappedException)
        { throw new UnauthorizedAccessException($"{file}: permessi non leggibili ({e.Message})"); }
        if (!IsTrustedOwner(security.GetOwner(typeof(SecurityIdentifier))))
            throw new UnauthorizedAccessException($"{file}: non appartiene agli amministratori");
    }

    /// <summary>True when the DACL is protected and every Allow entry names Administrators, SYSTEM or TrustedInstaller (or, when allowed, gives Users read only).</summary>
    internal static bool IsStrict(DirectorySecurity security, bool allowReaders = false)
    {
        if (!security.AreAccessRulesProtected) return false;
        const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Deny) continue;
            if (IsTrustedOwner(rule.IdentityReference)) continue;
            if (allowReaders && rule.IdentityReference is SecurityIdentifier sid && sid == Users && (rule.FileSystemRights & writes) == 0) continue;
            return false;
        }
        return true;
    }
}
