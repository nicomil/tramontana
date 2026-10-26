using Windows.ApplicationModel;
using Windows.Management.Deployment;
using WinCleaner.Core;

namespace WinCleaner.Modules.Apps;

/// <summary>Microsoft Store (MSIX) apps installed for the current user.</summary>
public static class StoreApps
{
    public static List<InstalledProgram> List()
    {
        var result = new List<InstalledProgram>();
        try
        {
            var manager = new PackageManager();
            foreach (var package in manager.FindPackagesForUser(string.Empty))
            {
                try
                {
                    if (package.IsFramework || package.IsResourcePackage || package.IsBundle) continue;
                    if (package.SignatureKind == PackageSignatureKind.System) continue;
                    if (package.IsStub) continue;
                    string name = package.DisplayName;
                    if (string.IsNullOrWhiteSpace(name) || name.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)) continue;
                    string? location = null;
                    try { location = package.InstalledLocation?.Path; } catch (Exception) { }
                    var v = package.Id.Version;
                    result.Add(new InstalledProgram
                    {
                        Id = "msix:" + package.Id.FullName,
                        Name = name,
                        Publisher = package.PublisherDisplayName,
                        Version = $"{v.Major}.{v.Minor}.{v.Build}.{v.Revision}",
                        InstallDate = package.InstalledDate.LocalDateTime,
                        InstallLocation = location,
                        Source = ProgramSource.Store,
                        PerUser = true,
                        PackageFullName = package.Id.FullName,
                        PackageFamilyName = package.Id.FamilyName,
                    });
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
        return result;
    }

    /// <summary>The app's data folder: %LOCALAPPDATA%\Packages\&lt;family name&gt;.</summary>
    public static string DataFolder(string familyName) => Path.Combine(KnownPaths.LocalAppData, "Packages", familyName);

    /// <summary>Removes a Store app for the current user (Windows removes its data folder too).</summary>
    public static async Task<string?> RemoveAsync(string fullName)
    {
        try
        {
            var result = await new PackageManager().RemovePackageAsync(fullName);
            return result.IsRegistered ? result.ErrorText : null;
        }
        catch (Exception e)
        {
            return e.Message;
        }
    }
}
