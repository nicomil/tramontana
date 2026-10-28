using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Tramontana.Core;

namespace Tramontana.Modules.Helper;

/// <summary>
/// The app's side of the elevated helper. One administrator prompt starts
/// the helper, which then serves requests until the app closes.
///
/// The helper (trhelper.exe) is started from the app's folder. Installed in
/// Program Files only administrators can swap it; anywhere else the app logs
/// that it is running from an unprotected folder (development). The pipe
/// accepts only the current user and one connection, the app checks that the
/// connected process runs an image with the same SHA-256 it computed, and the
/// helper in turn checks that the pipe belongs to Tramontana.exe in its own
/// folder (see <see cref="HelperIdentity"/>).
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

    public static string HelperPath => Path.Combine(AppContext.BaseDirectory, "trhelper.exe");

    /// <summary>True when the app folder can only be changed by administrators.</summary>
    public static bool IsInstalledLocation(string folder) =>
        PathGuard.IsStrictlyInside(folder, KnownPaths.ProgramFiles) || PathGuard.IsStrictlyInside(folder, KnownPaths.ProgramFilesX86);

    /// <summary>Starts the helper with an administrator prompt. Throws OperationCanceledException if the user declines.</summary>
    public static async Task<HelperClient> StartAsync(CancellationToken cancellation)
    {
        string helper = HelperPath;
        if (!File.Exists(helper)) throw new FileNotFoundException("trhelper.exe non trovato accanto all'app", helper);
        string hash = PipeSecurityChecks.Sha256(helper);
        string pipeName = "Tramontana-" + Guid.NewGuid().ToString("N");
        if (!IsInstalledLocation(Path.GetDirectoryName(helper)!))
            OperationLog.Standard.Write($"helper\tavvio da cartella non protetta (sviluppo)\t{helper}");

        var security = new PipeSecurity();
        var user = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 1 << 16, 1 << 16, security);

        var start = new ProcessStartInfo(helper, $"--pipe {pipeName} --parent {Environment.ProcessId}")
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
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
            throw new UnauthorizedAccessException("Il processo collegato non è l'helper di Tramontana");
        }

        var client = new HelperClient(pipe);
        HelperResponse ping;
        try { ping = await client.SendAsync(new HelperRequest { Operation = HelperOperation.Ping }, cancellation); }
        catch (IOException)
        {
            await client.DisposeAsync();
            throw new UnauthorizedAccessException("L'helper ha rifiutato il collegamento: Tramontana deve essere avviato dalla sua cartella di installazione");
        }
        if (!ping.Ok) throw new IOException("L'helper non risponde");
        return client;
    }

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
