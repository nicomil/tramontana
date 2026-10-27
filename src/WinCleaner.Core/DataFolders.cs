namespace WinCleaner.Core;

/// <summary>
/// Where WinCleaner keeps its own data. The app uses %LOCALAPPDATA%\WinCleaner;
/// the elevated helper switches to an administrator-only folder under
/// ProgramData (see <see cref="SecureFolder"/>), so that nothing it writes as
/// administrator goes through a path the user controls.
/// </summary>
public static class DataFolders
{
    public static string Root { get; private set; } = Path.Combine(KnownPaths.LocalAppData, "WinCleaner");
    public static string Logs => Path.Combine(Root, "Logs");
    public static string Backups => Path.Combine(Root, "Backups");

    /// <summary>The user's folder, whatever the current process uses (for the screens that open it).</summary>
    public static string UserRoot => Path.Combine(KnownPaths.LocalAppData, "WinCleaner");

    /// <summary>The helper's folder, for the screens that mention it.</summary>
    public static string HelperRoot => Path.Combine(KnownPaths.ProgramData, "WinCleaner", "Helper");

    public static void Use(string root)
    {
        Root = root;
        OperationLog.ResetStandard();
    }
}
