namespace Tramontana.Core;

/// <summary>
/// Where Tramontana keeps its own data. The app uses %LOCALAPPDATA%\Tramontana;
/// the elevated helper switches to an administrator-only folder under
/// ProgramData (see <see cref="SecureFolder"/>), so that nothing it writes as
/// administrator goes through a path the user controls.
/// </summary>
public static class DataFolders
{
    public static string Root { get; private set; } = Path.Combine(KnownPaths.LocalAppData, "Tramontana");
    public static string Logs => Path.Combine(Root, "Logs");
    public static string Backups => Path.Combine(Root, "Backups");

    /// <summary>The user's folder, whatever the current process uses (for the screens that open it).</summary>
    public static string UserRoot => Path.Combine(KnownPaths.LocalAppData, "Tramontana");

    /// <summary>
    /// The folder the administrator-only data (system quarantine, rule pins, helper logs) hangs
    /// from: ProgramData, where <see cref="SecureFolder.Ensure(string, string[])"/> creates
    /// <c>Tramontana</c> and its children. The tests point it at a temporary folder so that
    /// they never touch the machine's real quarantine.
    /// </summary>
    public static string SystemParent { get; private set; } = KnownPaths.ProgramData;

    /// <summary><see cref="SystemParent"/>\Tramontana.</summary>
    public static string SystemRoot => Path.Combine(SystemParent, "Tramontana");

    /// <summary>The helper's folder, for the screens that mention it.</summary>
    public static string HelperRoot => Path.Combine(SystemRoot, "Helper");

    public static void Use(string root)
    {
        Root = root;
        OperationLog.ResetStandard();
    }

    /// <summary>For the tests only: hangs the administrator-only data from another folder.</summary>
    internal static void UseSystem(string parent) => SystemParent = parent;
}
