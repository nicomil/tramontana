using System.Reflection;
using WinCleaner.Core;

namespace WinCleaner.Modules.Helper;

/// <summary>
/// Who may drive the elevated helper. The helper only serves the WinCleaner
/// app sitting in its own folder: the pipe server's image must be
/// WinCleaner.exe next to wchelper.exe, run by the same user, and in a
/// published build WinCleaner.dll must have the SHA-256 compiled into the
/// helper by publish.ps1. Without that, any program could start the helper
/// with a UAC prompt in WinCleaner's name and use it as its own administrator.
/// </summary>
public static class HelperIdentity
{
    public const string AppHashMetadata = "WinCleaner.AppSha256";
    public const string SignerMetadata = "WinCleaner.SignerThumbprint";
    private static readonly string[] CallerNames = ["WinCleaner.exe", "wccli.exe"];

    /// <summary>The SHA-256 of WinCleaner.dll the helper was published with, or null in a development build.</summary>
    public static string? ExpectedAppHash(Assembly? helper = null) => Metadata(AppHashMetadata, helper);

    /// <summary>The SHA-1 thumbprint of the code-signing certificate the app was signed with, or null in an unsigned build.</summary>
    public static string? ExpectedSigner(Assembly? helper = null) => Metadata(SignerMetadata, helper);

    private static string? Metadata(string key, Assembly? helper)
    {
        var assembly = helper ?? Assembly.GetEntryAssembly();
        var value = assembly?.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == key)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>
    /// Why the process at the other end of the pipe must not be served, or
    /// null when it is the app. <paramref name="sameUser"/> says whether the
    /// caller runs under the same account as the helper.
    /// </summary>
    public static string? Objection(string? callerImage, string helperDirectory, string? expectedAppHash, bool sameUser, string? expectedSigner = null)
    {
        if (!sameUser) return "il processo chiamante appartiene a un altro utente";
        if (callerImage is null || !PathGuard.IsValidPath(callerImage)) return "processo chiamante sconosciuto";
        string name = Path.GetFileName(callerImage);
        string folder = KnownPaths.Long(Path.GetDirectoryName(callerImage) ?? "");
        if (!string.Equals(folder, KnownPaths.Long(helperDirectory), StringComparison.OrdinalIgnoreCase))
            return $"il chiamante ({callerImage}) non sta nella cartella dell'helper";
        if (expectedAppHash is not null)
        {
            if (!name.Equals("WinCleaner.exe", StringComparison.OrdinalIgnoreCase)) return $"il chiamante ({name}) non è WinCleaner.exe";
            string dll = Path.Combine(folder, "WinCleaner.dll");
            string actual;
            try { actual = PipeSecurityChecks.Sha256(dll); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return "WinCleaner.dll non leggibile: " + e.Message; }
            if (!actual.Equals(expectedAppHash, StringComparison.OrdinalIgnoreCase)) return "WinCleaner.dll non è la versione per cui l'helper è stato pubblicato";
            // A signed build: the caller's executable must carry an intact signature made with the publisher's certificate.
            if (expectedSigner is not null && !Signatures.IsSignedBy(callerImage, expectedSigner)) return "WinCleaner.exe non ha la firma dell'editore attesa";
            return null;
        }
        // Development build: no hash compiled in, so only the folder and the name can be checked.
        if (!CallerNames.Contains(name, StringComparer.OrdinalIgnoreCase)) return $"il chiamante ({name}) non è WinCleaner";
        return null;
    }

    /// <summary>True when the folder can only be changed by administrators (Program Files).</summary>
    public static bool IsProtectedFolder(string folder) => HelperClient.IsInstalledLocation(folder);
}
