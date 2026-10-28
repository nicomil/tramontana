using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Tramontana.Core;

namespace Tramontana.Modules.Apps;

/// <summary>
/// Installers (.exe, .msi, .msix, .appx) left in Downloads and on the Desktop.
/// An installer is preselected only when Windows marked it as downloaded from
/// the internet (Mark of the Web) and the same program is already installed
/// in the same or a newer version: it can always be downloaded again.
/// </summary>
public sealed class InstallersModule : ICleanerModule
{
    public string Id => "installers";
    public string Title => "Installer";

    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle" };

    public IReadOnlyList<string> AllowedRoots => [KnownPaths.Downloads, KnownPaths.Desktop];

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        progress?.Report("Ricerca degli installer…");
        var installed = InstalledPrograms.All(includeStore: false);
        var files = new List<FileRecord>();
        files.AddRange(UserFilesWalker.Walk([KnownPaths.Downloads], 100_000, cancellation));
        if (Directory.Exists(KnownPaths.Desktop))
        {
            foreach (var f in new DirectoryInfo(KnownPaths.Desktop).EnumerateFiles())
                if (f.Length >= 100_000) files.Add(new FileRecord(f.FullName, f.Length, f.LastWriteTimeUtc, f.LastAccessTimeUtc, f.Attributes));
        }

        var items = new List<ScanItem>();
        foreach (var file in files.Where(f => Extensions.Contains(Path.GetExtension(f.Path))))
        {
            cancellation.ThrowIfCancellationRequested();
            var (product, version) = ProductOf(file.Path);
            var match = product is null ? null : FindInstalled(product, installed);
            bool fromInternet = ZoneOf(file.Path) >= 3;
            bool sameOrNewer = match is not null && (version is null || match.Version is null || CompareVersions(match.Version, version) >= 0);
            string detail = match is not null
                ? $"{match.Name} {match.Version} è già installato" + (fromInternet ? "" : " · non scaricato da internet")
                : (product is not null ? $"{product}{(version is null ? "" : " " + version)} · non installato" : "Installer");
            items.Add(new ScanItem(file.Path, file.Size, RiskLevel.Medium, fromInternet && sameOrNewer, false, detail, file.LastWriteUtc));
        }

        var categories = new List<ScanCategory>();
        var used = items.Where(i => i.AutoSelect).OrderByDescending(i => i.Size).ToList();
        var others = items.Where(i => !i.AutoSelect).OrderByDescending(i => i.Size).ToList();
        if (used.Count > 0) categories.Add(new ScanCategory("installers-used", "Installer di programmi già installati", used) { Group = "installers" });
        if (others.Count > 0) categories.Add(new ScanCategory("installers-other", "Altri installer", others) { Group = "installers" });
        return new ScanReport(Id, categories);
    }, cancellation);

    /// <summary>Zone of the Mark of the Web (3 = internet, 4 = untrusted), or 0 when absent.</summary>
    public static int ZoneOf(string path)
    {
        try
        {
            foreach (var line in File.ReadLines(path + ":Zone.Identifier"))
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase) && int.TryParse(line[7..].Trim(), out int zone))
                    return zone;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) { }
        return 0;
    }

    /// <summary>Product name and version from the version resource (exe) or the Property table (msi).</summary>
    public static (string? Product, string? Version) ProductOf(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".msi", StringComparison.OrdinalIgnoreCase))
            return (MsiProperty(path, "ProductName"), MsiProperty(path, "ProductVersion"));
        if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                string? name = string.IsNullOrWhiteSpace(info.ProductName) ? info.FileDescription : info.ProductName;
                return (string.IsNullOrWhiteSpace(name) ? null : name.Trim(), info.ProductVersion?.Trim());
            }
            catch (FileNotFoundException) { }
        }
        // MSIX file names: Publisher.App_1.2.3.0_x64__hash.msix
        var stem = Path.GetFileNameWithoutExtension(path);
        var parts = stem.Split('_');
        return parts.Length >= 2 ? (parts[0], parts[1]) : (stem, null);
    }

    internal static InstalledProgram? FindInstalled(string product, IReadOnlyList<InstalledProgram> installed)
    {
        string wanted = Simplify(LeftoverFinder.NormalizeName(product));
        if (wanted.Length < 3 || wanted is "setup" or "installer" or "install") return null;
        return installed.FirstOrDefault(p =>
        {
            string name = Simplify(LeftoverFinder.NormalizeName(p.Name));
            return name.Length >= 3 && (name == wanted || name.StartsWith(wanted + " ") || wanted.StartsWith(name + " "));
        });
    }

    private static string Simplify(string s) =>
        new string(s.ToLowerInvariant().Where(c => char.IsLetterOrDigit(c) || c == ' ').ToArray()).Replace("  ", " ").Trim();

    /// <summary>Numeric comparison of dotted versions ("10.2" &gt; "9.15").</summary>
    public static int CompareVersions(string a, string b)
    {
        var pa = a.Split('.', '-', ' ', '_');
        var pb = b.Split('.', '-', ' ', '_');
        for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            long.TryParse(i < pa.Length ? new string(pa[i].TakeWhile(char.IsDigit).ToArray()) : "0", out long x);
            long.TryParse(i < pb.Length ? new string(pb[i].TakeWhile(char.IsDigit).ToArray()) : "0", out long y);
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern uint MsiOpenDatabase(string path, IntPtr persist, out IntPtr handle);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern uint MsiDatabaseOpenView(IntPtr database, string query, out IntPtr view);
    [DllImport("msi.dll")]
    private static extern uint MsiViewExecute(IntPtr view, IntPtr record);
    [DllImport("msi.dll")]
    private static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern uint MsiRecordGetString(IntPtr record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll")]
    private static extern uint MsiCloseHandle(IntPtr handle);

    private static string? MsiProperty(string path, string property)
    {
        if (MsiOpenDatabase(path, IntPtr.Zero /* read only */, out var db) != 0) return null;
        try
        {
            if (MsiDatabaseOpenView(db, $"SELECT `Value` FROM `Property` WHERE `Property`='{property}'", out var view) != 0) return null;
            try
            {
                if (MsiViewExecute(view, IntPtr.Zero) != 0 || MsiViewFetch(view, out var record) != 0) return null;
                try
                {
                    var buffer = new StringBuilder(512);
                    uint length = (uint)buffer.Capacity;
                    return MsiRecordGetString(record, 1, buffer, ref length) == 0 ? buffer.ToString() : null;
                }
                finally { MsiCloseHandle(record); }
            }
            finally { MsiCloseHandle(view); }
        }
        finally { MsiCloseHandle(db); }
    }
}
