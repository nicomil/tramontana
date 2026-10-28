namespace Tramontana.Core;

/// <summary>
/// Checks the shape of paths before anything touches them. Only plain local
/// paths like <c>C:\Users\me\AppData\Local\Temp\x</c> are accepted: no UNC or
/// device paths (<c>\\server</c>, <c>\\?\</c>, <c>\\.\</c>), no "." or "..",
/// no alternate data streams (<c>file:stream</c>), no names ending with a dot
/// or a space (Win32 drops them, so the name checked would differ from the
/// name removed), no forward slashes and no wildcards.
/// </summary>
public static class PathGuard
{
    private const string InvalidNameChars = "<>:\"/\\|?*";

    /// <summary>True for a single valid file or folder name.</summary>
    public static bool IsValidName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 255) return false;
        if (name is "." or "..") return false;
        if (name[^1] is '.' or ' ') return false;
        foreach (char c in name)
        {
            if (c < 0x20 || InvalidNameChars.Contains(c)) return false;
        }
        return true;
    }

    /// <summary>
    /// Splits a path into its drive root (<c>C:\</c>) and components, or
    /// returns false when the path is not a plain local absolute path.
    /// </summary>
    public static bool TrySplit(string path, out string driveRoot, out string[] components)
    {
        driveRoot = "";
        components = [];
        if (string.IsNullOrEmpty(path) || path.Length > 32_000) return false;
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') return false;
        driveRoot = char.ToUpperInvariant(path[0]) + @":\";
        if (path.Length == 3) return true;
        if (path[^1] == '\\') return false;
        var parts = path[3..].Split('\\');
        foreach (var part in parts)
        {
            if (!IsValidName(part)) return false;
        }
        components = parts;
        return true;
    }

    public static bool IsValidPath(string path) => TrySplit(path, out _, out _);

    /// <summary>
    /// True when <paramref name="path"/> is strictly inside <paramref name="root"/>.
    /// Both must be valid paths; the comparison ignores case, as NTFS does.
    /// </summary>
    public static bool IsStrictlyInside(string path, string root)
    {
        var r = root.TrimEnd('\\');
        return path.Length > r.Length + 1
               && path.StartsWith(r, StringComparison.OrdinalIgnoreCase)
               && path[r.Length] == '\\';
    }

    public static bool IsSameOrInside(string path, string root) =>
        string.Equals(path.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
        IsStrictlyInside(path, root);

    /// <summary>The components of <paramref name="path"/> below <paramref name="root"/>.</summary>
    public static string[] RelativeComponents(string path, string root)
    {
        var r = root.TrimEnd('\\');
        return path[(r.Length + 1)..].Split('\\');
    }
}
