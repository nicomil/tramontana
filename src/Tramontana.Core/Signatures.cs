using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Tramontana.Core;

/// <summary>
/// <see cref="Untrusted"/> is a signature whose hash is intact but whose certificate chain
/// Windows does not trust (self-signed, private CA, expired): the file is not modified, its
/// publisher is just unknown. <see cref="Invalid"/> means the file no longer matches its signature.
/// </summary>
public enum SignatureStatus { Signed, Unsigned, Invalid, Missing, Untrusted }

/// <summary>
/// Outcome of a signature check. <paramref name="MicrosoftRoot"/> is set by the
/// real check (the signer chains to one of Microsoft's own roots, or the file
/// is in a Windows catalog); when null, as in the test doubles, the publisher
/// name decides.
/// </summary>
public sealed record SignatureInfo(SignatureStatus Status, string? Publisher, bool? MicrosoftRoot = null)
{
    public bool IsMicrosoft => MicrosoftRoot ?? Publisher?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>
/// Authenticode checks with WinVerifyTrust (no network: revocation is not
/// checked, so a scan never waits on a certificate server). Files without an
/// embedded signature are looked up in the Windows security catalogs, the way
/// Windows components are signed. "Microsoft" means the signer's chain ends in
/// a Microsoft root, not that the name starts with Microsoft.
/// </summary>
public static unsafe partial class Signatures
{
    private static readonly Dictionary<string, SignatureInfo> Cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>SHA-1 thumbprints of the roots Microsoft signs Windows and its products with.</summary>
    internal static readonly HashSet<string> MicrosoftRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "A43489159A520F0D93D032CCAF37E7FE20A8B419", // Microsoft Root Authority
        "CDD4EEAE6000AC7F40C3802C171E30148030C072", // Microsoft Root Certificate Authority
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5", // Microsoft Root Certificate Authority 2010
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE", // Microsoft Root Certificate Authority 2011
        "999A64C37FF47D9FAB95F14769891460EEC4C3C5", // Microsoft ECC Root Certificate Authority 2017
        "06F1AA330B927B753A40E68CDF22E34BCBEF3352", // Microsoft ECC Product Root Certificate Authority 2018
    };

    public static SignatureInfo Check(string path)
    {
        lock (Cache) { if (Cache.TryGetValue(path, out var cached)) return cached; }
        var result = CheckUncached(path);
        lock (Cache) Cache[path] = result;
        return result;
    }

    private static SignatureInfo CheckUncached(string path)
    {
        if (!File.Exists(path)) return new SignatureInfo(SignatureStatus.Missing, null);
        int trust = VerifyEmbedded(path);
        if (trust == 0)
        {
            var (publisher, microsoft) = Signer(path);
            return new SignatureInfo(SignatureStatus.Signed, publisher, microsoft);
        }
        // TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN
        bool unsigned = trust is unchecked((int)0x800B0100) or unchecked((int)0x800B0003) or unchecked((int)0x800B0001);
        if (unsigned)
        {
            if (VerifyCatalog(path)) return new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows", true);
            // The catalog lookup can fail on a component that is still Windows's (a catalog not
            // installed, a build mismatch): only the folders nobody but TrustedInstaller writes to
            // get the benefit of the doubt. Windows\Temp, Tasks and the other user-writable corners
            // of the Windows folder do not.
            if (IsComponentFolder(path)) return new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows", true);
            return new SignatureInfo(SignatureStatus.Unsigned, null, false);
        }
        var (name, _) = Signer(path);
        return new SignatureInfo(Classify(trust), name, false);
    }

    /// <summary>
    /// What a non-zero WinVerifyTrust result means for a file that does carry a signature:
    /// a chain problem (CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED,
    /// CERT_E_PURPOSE, CERT_E_WRONG_USAGE, CERT_E_CN_NO_MATCH) leaves the file intact and the
    /// publisher unknown; anything else (bad digest, malformed signature) is a modified file.
    /// </summary>
    internal static SignatureStatus Classify(int trust) => trust switch
    {
        0 => SignatureStatus.Signed,
        unchecked((int)0x800B0109) or unchecked((int)0x800B010A) or unchecked((int)0x800B0101) or unchecked((int)0x800B010C)
            or unchecked((int)0x800B0106) or unchecked((int)0x800B0110) or unchecked((int)0x800B010F) => SignatureStatus.Untrusted,
        _ => SignatureStatus.Invalid,
    };

    /// <summary>
    /// True when the file carries a valid Authenticode signature (hash intact) made with the
    /// certificate whose SHA-1 thumbprint is <paramref name="thumbprint"/>. The chain need not
    /// end in a trusted root: the pinned thumbprint is the trust, so a self-signed publisher
    /// certificate works as well as one from a public CA.
    /// </summary>
    public static bool IsSignedBy(string path, string thumbprint)
    {
        if (!File.Exists(path) || string.IsNullOrWhiteSpace(thumbprint)) return false;
        int trust = VerifyEmbedded(path);
        const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
        const int CERT_E_CHAINING = unchecked((int)0x800B010A);
        if (trust is not (0 or CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING)) return false;
        try
        {
#pragma warning disable SYSLIB0057
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return string.Equals(signer.Thumbprint, thumbprint.Replace(" ", ""), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception) { return false; }
    }

    internal static bool IsComponentFolder(string path) =>
        new[] { "System32", "SysWOW64", "WinSxS", "servicing", "SystemApps", "ImmersiveControlPanel" }
            .Any(f => PathGuard.IsStrictlyInside(path, Path.Combine(KnownPaths.Windows, f)))
        && !path.Contains(@"\System32\Tasks\", StringComparison.OrdinalIgnoreCase)
        && !path.Contains(@"\System32\spool\drivers\color\", StringComparison.OrdinalIgnoreCase);

    /// <summary>The signer's simple name and whether its chain ends in a Microsoft root.</summary>
    private static (string? Publisher, bool Microsoft) Signer(string path)
    {
        X509Certificate2? leaf = null;
        var extra = new X509Certificate2Collection();
        try
        {
#pragma warning disable SYSLIB0057
            leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            extra.Import(path);
#pragma warning restore SYSLIB0057
        }
        catch (Exception) { }
        if (leaf is null) return (null, false);
        string? publisher = null;
        try { publisher = leaf.GetNameInfo(X509NameType.SimpleName, false); } catch (Exception) { }
        bool microsoft;
        try { microsoft = ChainsToMicrosoft(leaf, extra); } catch (Exception) { microsoft = false; }
        return (publisher, microsoft);
    }

    /// <summary>
    /// Builds the signer's chain offline (the intermediates come from the file)
    /// and accepts a Microsoft root by thumbprint; a Microsoft subject under a
    /// root trusted machine-wide also counts, one installed only for the current
    /// user (which a user-level program can do) never does.
    /// </summary>
    internal static bool ChainsToMicrosoft(X509Certificate2 leaf, X509Certificate2Collection extra)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreNotTimeNested
            | X509VerificationFlags.IgnoreCtlNotTimeValid | X509VerificationFlags.IgnoreEndRevocationUnknown
            | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown | X509VerificationFlags.IgnoreRootRevocationUnknown
            | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown;
        chain.ChainPolicy.ExtraStore.AddRange(extra);
        bool built = chain.Build(leaf);
        if (chain.ChainElements.Count == 0) return false;
        var root = chain.ChainElements[^1].Certificate;
        if (!string.Equals(root.Subject, root.Issuer, StringComparison.OrdinalIgnoreCase)) return false; // chain incomplete
        if (MicrosoftRoots.Contains(root.Thumbprint)) return true;
        if (!built) return false;
        return leaf.Subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) && IsMachineTrustedRoot(root.Thumbprint);
    }

    private static HashSet<string>? _machineRoots;

    private static bool IsMachineTrustedRoot(string thumbprint)
    {
        var roots = _machineRoots;
        if (roots is null)
        {
            roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var cert in store.Certificates) roots.Add(cert.Thumbprint);
            }
            catch (System.Security.Cryptography.CryptographicException) { }
            _machineRoots = roots;
        }
        return roots.Contains(thumbprint);
    }

    // ---- WinVerifyTrust ----

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        public fixed char wszCatalogFile[260];
    }

    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_PROV_FLAGS = 0x1000 | 0x10; // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [LibraryImport("wintrust.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminAcquireContext2(out IntPtr admin, in Guid subsystem, string? hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint hashSize, byte* hash, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    private static partial IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte* hash, uint hashSize, uint flags, ref IntPtr previous);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CATALOG_INFO info, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

    private static int VerifyEmbedded(string path)
    {
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(file, filePtr, false);
            return Verify(GenericVerifyV2, WTD_CHOICE_FILE, filePtr);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(filePtr);
        }
    }

    private static int Verify(Guid action, uint choice, IntPtr union)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = choice,
            pUnion = union,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_PROV_FLAGS,
        };
        int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        return result;
    }

    /// <summary>
    /// True when the file's hash is a member of a signed catalog in the catalog
    /// database (how Windows's own files are signed) and the catalog verifies.
    /// </summary>
    internal static bool VerifyCatalog(string path)
    {
        IntPtr admin = IntPtr.Zero;
        IntPtr catalog = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out admin, in DriverActionVerify, "SHA256", IntPtr.Zero, 0)) return false;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, null, 0);
            if (size == 0 || size > 128) return false;
            byte* hash = stackalloc byte[(int)size];
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, hash, 0)) return false;
            IntPtr previous = IntPtr.Zero;
            catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
            if (catalog == IntPtr.Zero) return false;
            var info = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
            if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) return false;
            string catalogFile = new string(info.wszCatalogFile).TrimEnd('\0');
            string tag = Convert.ToHexString(new ReadOnlySpan<byte>(hash, (int)size));

            IntPtr catalogPath = Marshal.StringToHGlobalUni(catalogFile);
            IntPtr memberTag = Marshal.StringToHGlobalUni(tag);
            IntPtr memberPath = Marshal.StringToHGlobalUni(path);
            IntPtr infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                var catalogInfo = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catalogPath,
                    pcwszMemberTag = memberTag,
                    pcwszMemberFilePath = memberPath,
                    hMemberFile = stream.SafeFileHandle.DangerousGetHandle(),
                    pbCalculatedFileHash = (IntPtr)hash,
                    cbCalculatedFileHash = size,
                    hCatAdmin = admin,
                };
                Marshal.StructureToPtr(catalogInfo, infoPtr, false);
                return Verify(GenericVerifyV2, WTD_CHOICE_CATALOG, infoPtr) == 0;
            }
            finally
            {
                Marshal.FreeHGlobal(infoPtr);
                Marshal.FreeHGlobal(catalogPath);
                Marshal.FreeHGlobal(memberTag);
                Marshal.FreeHGlobal(memberPath);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or EntryPointNotFoundException or DllNotFoundException)
        {
            return false;
        }
        finally
        {
            if (catalog != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
        }
    }
}
