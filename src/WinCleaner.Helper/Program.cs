using System.IO.Pipes;
using System.Text;
using WinCleaner.Modules.Helper;

// wchelper: the only part of WinCleaner that runs as administrator. It
// connects to the pipe created by the app that started it, checks that the
// pipe belongs to that process, then serves one request per line until the
// app closes the pipe (or after 30 minutes without requests).
string? pipeName = null;
int parent = 0;
for (int i = 0; i + 1 < args.Length; i++)
{
    if (args[i] == "--pipe") pipeName = args[i + 1];
    if (args[i] == "--parent") int.TryParse(args[i + 1], out parent);
}
if (pipeName is null || !pipeName.StartsWith("WinCleaner-", StringComparison.Ordinal) || parent <= 0) return 2;
if (!HelperService.IsElevated()) return 5;

using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
await pipe.ConnectAsync(10_000);
if (PipeSecurityChecks.ServerProcessId(pipe) != (uint)parent) return 6;

using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 1 << 16, leaveOpen: true);
using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 1 << 16, leaveOpen: true) { AutoFlush = true };
while (true)
{
    using var idle = new CancellationTokenSource(TimeSpan.FromMinutes(30));
    string? line;
    try { line = await reader.ReadLineAsync(idle.Token); }
    catch (OperationCanceledException) { break; }
    catch (IOException) { break; }
    if (line is null) break;
    HelperResponse response;
    var request = HelperJson.Deserialize<HelperRequest>(line);
    if (request is null) response = new HelperResponse { Ok = false, Error = "Richiesta non valida" };
    else response = await HelperService.HandleAsync(request, CancellationToken.None);
    try { await writer.WriteLineAsync(HelperJson.Serialize(response)); }
    catch (IOException) { break; }
}
return 0;
