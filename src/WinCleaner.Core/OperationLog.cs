namespace WinCleaner.Core;

/// <summary>
/// Appends one line per operation to a plain text log, so every removal can
/// be traced afterwards. The file is rotated at 5 MB (one old copy is kept).
/// </summary>
public sealed class OperationLog
{
    private readonly object _lock = new();
    public string FilePath { get; }

    public OperationLog(string filePath) => FilePath = filePath;

    /// <summary><see cref="DataFolders.Logs"/>\operations.log: the user's folder in the app, the administrator-only folder in the helper.</summary>
    public static OperationLog Standard { get; private set; } = new(Path.Combine(DataFolders.Logs, "operations.log"));

    internal static void ResetStandard() => Standard = new(Path.Combine(DataFolders.Logs, "operations.log"));

    public void Record(RemovalMode mode, RemovalOutcome outcome)
    {
        string result = outcome.Error is { } error
            ? $"ERR {error}{(outcome.Message is null ? "" : $" ({outcome.Message})")}"
            : $"OK {outcome.Freed}{(outcome.InUse > 0 ? $" inuse={outcome.InUse}" : "")}";
        Write($"{mode.ToString().ToLowerInvariant()}\t{result}\t{outcome.Path}");
    }

    public void Write(string line)
    {
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var info = new FileInfo(FilePath);
                if (info.Exists && info.Length > 5 * 1024 * 1024)
                    File.Move(FilePath, FilePath + ".1", overwrite: true);
                File.AppendAllText(FilePath, $"{DateTime.Now:yyyy-MM-ddTHH:mm:ss.fffzzz}\t{line}{Environment.NewLine}");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
