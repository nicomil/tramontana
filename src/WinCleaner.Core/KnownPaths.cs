using System.Runtime.InteropServices;

namespace WinCleaner.Core;

/// <summary>
/// Standard folders, always as full long paths (never 8.3 short names such as
/// <c>C:\Users\NICOLA~1</c>, which %TEMP% sometimes uses), so that prefix
/// checks against allowed roots work.
/// </summary>
public static partial class KnownPaths
{
    public static string UserProfile => Long(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    public static string LocalAppData => Long(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
    public static string RoamingAppData => Long(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
    public static string LocalAppDataLow => Path.Combine(UserProfile, "AppData", "LocalLow");
    public static string ProgramData => Long(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
    public static string Windows => Long(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    /// <summary>The drive Windows is on, taken from the Windows folder (not from %SystemDrive%, which a user can override).</summary>
    public static string SystemDrive => Path.GetPathRoot(Windows) ?? @"C:\";
    public static string ProgramFiles => Long(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    public static string ProgramFilesX86 => Long(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
    /// <summary>The Public profile from the shell (FOLDERID_Public), not from %PUBLIC%, which a user can override.</summary>
    public static string Public => Long(GetKnownFolder(new Guid("DFDF76A2-C82A-4D63-906A-5644AC457385")) ?? Path.Combine(SystemDrive, "Users", "Public"));
    public static string Downloads => Long(GetKnownFolder(new Guid("374DE290-123F-4565-9164-39C4925E467B")) ?? Path.Combine(UserProfile, "Downloads"));
    public static string Desktop => Long(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
    public static string Documents => Long(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
    public static string StartMenu => Long(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu));
    public static string CommonStartMenu => Long(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu));
    public static string Startup => Long(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
    public static string CommonStartup => Long(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
    public static string Recent => Long(Environment.GetFolderPath(Environment.SpecialFolder.Recent));

    /// <summary>The user's temporary folder (%TEMP%) as a long path, without the trailing backslash.</summary>
    public static string Temp => Long(Path.GetTempPath());

    /// <summary>
    /// Replaces the tokens used by the rules (%LOCALAPPDATA%, %APPDATA%,
    /// %TEMP%, %USERPROFILE%, %PROGRAMDATA%, %WINDIR%, %SYSTEMDRIVE%,
    /// %PROGRAMFILES%, %PROGRAMFILES(X86)%, %LOCALAPPDATALOW%, %PUBLIC%).
    /// Unknown tokens make the result null, so a rule never runs on a guessed path.
    /// </summary>
    public static string? Expand(string pattern)
    {
        var result = new System.Text.StringBuilder();
        int i = 0;
        while (i < pattern.Length)
        {
            if (pattern[i] != '%') { result.Append(pattern[i++]); continue; }
            int end = pattern.IndexOf('%', i + 1);
            if (end < 0) return null;
            string? value = pattern[(i + 1)..end].ToUpperInvariant() switch
            {
                "LOCALAPPDATA" => LocalAppData,
                "APPDATA" => RoamingAppData,
                "LOCALAPPDATALOW" => LocalAppDataLow,
                "TEMP" or "TMP" => Temp,
                "USERPROFILE" => UserProfile,
                "PROGRAMDATA" => ProgramData,
                "WINDIR" or "SYSTEMROOT" => Windows,
                "SYSTEMDRIVE" => SystemDrive.TrimEnd('\\'),
                "PROGRAMFILES" => ProgramFiles,
                "PROGRAMFILES(X86)" => ProgramFilesX86,
                "PUBLIC" => Public,
                "DOWNLOADS" => Downloads,
                _ => null,
            };
            if (string.IsNullOrEmpty(value)) return null;
            result.Append(value.TrimEnd('\\'));
            i = end + 1;
        }
        return result.ToString();
    }

    /// <summary>Long form of a path: expands 8.3 names and drops a trailing backslash (except for drive roots).</summary>
    public static string Long(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        string full = Path.GetFullPath(path);
        if (full.Contains('~'))
        {
            var buffer = new char[32_768];
            uint length = GetLongPathName(full, buffer, (uint)buffer.Length);
            if (length > 0 && length < buffer.Length) full = new string(buffer, 0, (int)length);
        }
        return full.Length > 3 ? full.TrimEnd('\\') : full;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetLongPathNameW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetLongPathName(string shortPath, [Out] char[] longPath, uint length);

    [LibraryImport("shell32.dll")]
    private static partial int SHGetKnownFolderPath(in Guid id, uint flags, IntPtr token, out IntPtr path);

    private static string? GetKnownFolder(Guid id)
    {
        if (SHGetKnownFolderPath(id, 0, IntPtr.Zero, out IntPtr raw) != 0) return null;
        try { return Marshal.PtrToStringUni(raw); }
        finally { Marshal.FreeCoTaskMem(raw); }
    }
}
