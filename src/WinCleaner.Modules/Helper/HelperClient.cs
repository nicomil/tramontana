using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WinCleaner.Core;

namespace WinCleaner.Modules.Helper;

/// <summary>
/// The app's side of the elevated helper. One administrator prompt starts
/// the helper, which then serves requests until the app closes.
///
/// The helper (wchelper.exe) is started directly when the app is installed
/// in Program Files, where only administrators can write. Otherwise an
/// elevated Windows PowerShell first copies it into a new folder under
/// C:\Windows\Temp that only administrators and SYSTEM can open, checks its
/// SHA-256 against the value computed by the app, and only then runs that
/// copy, so a file swapped in the app folder while the prompt is open is
/// never run as administrator.
///
/// The pipe accepts only the current user, one connection, and the app
/// checks that the connected process runs an image with the same SHA-256.
/// </summary>
public sealed class HelperClient : IAsyncDisposable
{
    private readonly NamedPipeServerStream _pipe;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _nextId;

    private HelperClient(NamedPipeServerStream pipe)
    {
        _pipe = pipe;
        _reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1 << 16, leaveOpen: true);
        _writer = new StreamWriter(pipe, new UTF8Encoding(false), 1 << 16, leaveOpen: true) { AutoFlush = true };
    }

    public bool IsConnected => _pipe.IsConnected;

    public static string HelperPath => Path.Combine(AppContext.BaseDirectory, "wchelper.exe");

    /// <summary>True when the app folder can only be changed by administrators.</summary>
    public static bool IsInstalledLocation(string folder) =>
        PathGuard.IsStrictlyInside(folder, KnownPaths.ProgramFiles) || PathGuard.IsStrictlyInside(folder, KnownPaths.ProgramFilesX86);

    /// <summary>Starts the helper with an administrator prompt. Throws OperationCanceledException if the user declines.</summary>
    public static async Task<HelperClient> StartAsync(CancellationToken cancellation)
    {
        string helper = HelperPath;
        if (!File.Exists(helper)) throw new FileNotFoundException("wchelper.exe non trovato accanto all'app", helper);
        string hash = PipeSecurityChecks.Sha256(helper);
        string pipeName = "WinCleaner-" + Guid.NewGuid().ToString("N");

        var security = new PipeSecurity();
        var user = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 1 << 16, 1 << 16, security);

        string args = $"--pipe {pipeName} --parent {Environment.ProcessId}";
        var start = IsInstalledLocation(Path.GetDirectoryName(helper)!)
            ? new ProcessStartInfo(helper, args)
            : new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " +
                PipeSecurityChecks.EncodePowerShell(BootstrapScript(helper, hash, args)));
        start.UseShellExecute = true;
        start.Verb = "runas";
        start.WindowStyle = ProcessWindowStyle.Hidden;
        try
        {
            using var _ = Process.Start(start);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            await pipe.DisposeAsync();
            throw new OperationCanceledException("Richiesta di amministratore annullata");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            await pipe.WaitForConnectionAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            await pipe.DisposeAsync();
            throw new TimeoutException("L'helper di sistema non si è collegato");
        }

        // The connected process must run the very helper the app checked.
        var clientId = PipeSecurityChecks.ClientProcessId(pipe);
        var image = clientId is { } id ? PipeSecurityChecks.ImagePath(id) : null;
        if (image is null || !string.Equals(PipeSecurityChecks.Sha256(image), hash, StringComparison.OrdinalIgnoreCase))
        {
            await pipe.DisposeAsync();
            throw new UnauthorizedAccessException("Il processo collegato non è l'helper di WinCleaner");
        }

        var client = new HelperClient(pipe);
        var ping = await client.SendAsync(new HelperRequest { Operation = HelperOperation.Ping }, cancellation);
        if (!ping.Ok) throw new IOException("L'helper non risponde");
        return client;
    }

    /// <summary>Elevated Windows PowerShell: copy into an admin-only folder, verify the hash, run, clean up.</summary>
    internal static string BootstrapScript(string helper, string hash, string args) => $$"""
        $ErrorActionPreference = 'Stop'
        $dir = Join-Path $env:SystemRoot ('Temp\WinCleaner-' + [guid]::NewGuid().ToString('N'))
        $sec = New-Object System.Security.AccessControl.DirectorySecurity
        $sec.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
            $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $sec.AddAccessRule($rule)
        }
        [System.IO.Directory]::CreateDirectory($dir, $sec) | Out-Null
        try {
            $dst = Join-Path $dir 'wchelper.exe'
            [System.IO.File]::Copy({{PipeSecurityChecks.PsQuote(helper)}}, $dst)
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash -ne {{PipeSecurityChecks.PsQuote(hash)}}) { exit 3 }
            $p = Start-Process -FilePath $dst -ArgumentList {{PipeSecurityChecks.PsQuote(args)}} -PassThru -Wait -WindowStyle Hidden
            exit $p.ExitCode
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
        """;

    public async Task<HelperResponse> SendAsync(HelperRequest request, CancellationToken cancellation)
    {
        await _gate.WaitAsync(cancellation);
        try
        {
            request = request with { Id = Interlocked.Increment(ref _nextId) };
            await _writer.WriteLineAsync(HelperJson.Serialize(request).AsMemory(), cancellation);
            string? line = await _reader.ReadLineAsync(cancellation);
            if (line is null) throw new IOException("L'helper di sistema si è chiuso");
            return HelperJson.Deserialize<HelperResponse>(line) ?? throw new IOException("Risposta non valida dall'helper");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync();
        _gate.Dispose();
    }
}
