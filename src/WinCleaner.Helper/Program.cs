using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Protection.Processes;

// wchelper: the only part of WinCleaner that runs as administrator. It
// connects to the pipe created by the app that started it, checks that the
// pipe belongs to WinCleaner.exe in its own folder, then serves one request
// per line until the app closes the pipe (or after 10 minutes without requests).

// DLLs come only from the helper's folder and System32, never from the PATH of
// the user who started it.
Hardening.SetDefaultDllDirectories(0x0000_0800 | 0x0000_0200); // LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR

// "wchelper.exe --identity" prints the SHA-256 of the WinCleaner.dll this build serves (publish.ps1 checks it).
if (args.Length == 1 && args[0] == "--identity")
{
    Console.Out.Write((HelperIdentity.ExpectedAppHash() ?? "") + "|" + (HelperIdentity.ExpectedSigner() ?? ""));
    Console.Out.Flush();
    return 0;
}

string? pipeName = null;
int parent = 0;
for (int i = 0; i + 1 < args.Length; i++)
{
    if (args[i] == "--pipe") pipeName = args[i + 1];
    if (args[i] == "--parent") int.TryParse(args[i + 1], out parent);
}
if (pipeName is null || !pipeName.StartsWith("WinCleaner-", StringComparison.Ordinal) || parent <= 0) return 2;
if (!HelperService.IsElevated()) return 5;

// Everything the helper writes as administrator goes to a folder only administrators can change.
try
{
    string data = SecureFolder.Ensure(KnownPaths.ProgramData, "WinCleaner", "Helper");
    SecureFolder.Ensure(KnownPaths.ProgramData, "WinCleaner", "Helper", "Logs");
    SecureFolder.Ensure(KnownPaths.ProgramData, "WinCleaner", "Helper", "Backups");
    DataFolders.Use(data);
}
catch (Exception e) when (e is UnauthorizedAccessException or IOException or ArgumentException)
{
    return 8;
}

// A runtime hook in the environment means someone prepared this process: do not serve.
var hooks = ProcessEnvironment.HooksInCurrentProcess();
if (hooks.Count > 0)
{
    OperationLog.Standard.Write($"helper\trifiutato: variabili d'ambiente sospette\t{string.Join(",", hooks)}");
    return 9;
}

using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
await pipe.ConnectAsync(10_000);
var serverId = PipeSecurityChecks.ServerProcessId(pipe);
if (serverId != (uint)parent) return 6;

string helperFolder = AppContext.BaseDirectory;
string? callerImage = PipeSecurityChecks.ImagePath((uint)parent);
string? objection = HelperIdentity.Objection(callerImage, helperFolder, HelperIdentity.ExpectedAppHash(), SystemProcesses.IsOwnedByCurrentUser(parent), HelperIdentity.ExpectedSigner());
if (objection is not null)
{
    OperationLog.Standard.Write($"helper\trifiutato\t{objection}");
    return 7;
}
if (!HelperIdentity.IsProtectedFolder(helperFolder))
    OperationLog.Standard.Write($"helper\tavvio da cartella non protetta (sviluppo)\t{helperFolder}");

using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1 << 16, leaveOpen: true);
using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1 << 16, leaveOpen: true) { AutoFlush = true };
while (true)
{
    using var idle = new CancellationTokenSource(TimeSpan.FromMinutes(10));
    string? line;
    try { line = await reader.ReadLineAsync(idle.Token); }
    catch (OperationCanceledException) { break; }
    catch (IOException) { break; }
    if (line is null) break;
    HelperResponse response;
    HelperRequest? request = null;
    try { request = HelperJson.Deserialize<HelperRequest>(line); }
    catch (System.Text.Json.JsonException) { }
    if (request is null) response = new HelperResponse { Ok = false, Error = "Richiesta non valida" };
    else response = await HelperService.HandleAsync(request, CancellationToken.None);
    try { await writer.WriteLineAsync(HelperJson.Serialize(response)); }
    catch (IOException) { break; }
}
return 0;

internal static partial class Hardening
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetDefaultDllDirectories(uint flags);
}
