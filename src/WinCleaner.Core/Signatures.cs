using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace WinCleaner.Core;

public enum SignatureStatus { Signed, Unsigned, Invalid, Missing }

public sealed record SignatureInfo(SignatureStatus Status, string? Publisher)
{
    public bool IsMicrosoft => Publisher?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>
/// Authenticode checks with WinVerifyTrust (no network: revocation is not
/// checked, so a scan never waits on a certificate server). Windows files
/// signed through catalogs count as signed by Microsoft.
/// </summary>
public static partial class Signatures
{
    private static readonly Dictionary<string, SignatureInfo> Cache = new(StringComparer.OrdinalIgnoreCase);

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
        int trust = Verify(path);
        string? publisher = null;
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception) { }

        if (trust == 0) return new SignatureInfo(SignatureStatus.Signed, publisher);
        // TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN
        bool unsigned = trust is unchecked((int)0x800B0100) or unchecked((int)0x800B0003) or unchecked((int)0x800B0001);
        if (unsigned && PathGuard.IsStrictlyInside(path, KnownPaths.Windows))
            return new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows");
        return new SignatureInfo(unsigned ? SignatureStatus.Unsigned : SignatureStatus.Invalid, publisher);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
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
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    private static int Verify(string path)
    {
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(file, filePtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = filePtr,
                dwStateAction = 1,         // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x1000 | 0x10, // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(filePtr);
        }
    }
}
