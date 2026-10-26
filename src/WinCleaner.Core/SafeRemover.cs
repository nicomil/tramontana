using Microsoft.Win32.SafeHandles;
using static WinCleaner.Core.Native.NativeMethods;

namespace WinCleaner.Core;

/// <summary>What to do with the files the user chose to clean.</summary>
public enum RemovalMode
{
    /// <summary>Move to the Recycle Bin (default, can be undone).</summary>
    Recycle,
    /// <summary>Delete permanently.</summary>
    Delete,
    /// <summary>Do nothing, only report what would happen.</summary>
    DryRun,
}

/// <summary>Why a path was refused or failed.</summary>
public enum RemovalError
{
    InvalidPath,
    OutsideAllowedRoots,
    IsAllowedRoot,
    ReparsePointInPath,
    SystemProtected,
    NotFound,
    InUse,
    AccessDenied,
    RecycleBinUnavailable,
    Failed,
}

public sealed record RemovalOutcome(string Path, long Freed, RemovalError? Error, string? Message = null, int InUse = 0)
{
    public bool Succeeded => Error is null;
}

/// <summary>
/// Removes files only inside a fixed set of folders.
///
/// The path must be a plain local path strictly inside one of the allowed
/// roots. The root is opened, then every folder below it is opened relative to
/// its parent, one name at a time; a junction, symbolic link or mount point on
/// the way makes the removal fail. The item itself is removed through its
/// handle: links are removed as links, folders are emptied without entering
/// the links inside them, and files owned by TrustedInstaller or protected by
/// Windows Resource Protection are refused.
/// </summary>
public sealed class SafeRemover
{
    private readonly OperationLog? _log;

    public IReadOnlyList<string> AllowedRoots { get; }

    /// <summary>Paths that are never removed, nor any folder that contains them.</summary>
    public IReadOnlyList<string> ProtectedPaths { get; }

    /// <summary>
    /// Single items allowed outside the roots, as full paths whose last
    /// component may use wildcards (e.g. <c>C:\FOUND.*</c>, <c>C:\Windows\MEMORY.DMP</c>).
    /// </summary>
    public IReadOnlyList<string> AllowedItems { get; }

    public RemovalMode Mode { get; }

    public SafeRemover(IEnumerable<string> allowedRoots, RemovalMode mode, OperationLog? log = null,
        IEnumerable<string>? protectedPaths = null, IEnumerable<string>? allowedItems = null)
    {
        AllowedRoots = allowedRoots.Where(PathGuard.IsValidPath).Select(KnownPaths.Long)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        AllowedItems = (allowedItems ?? []).ToList();
        ProtectedPaths = (protectedPaths ?? DefaultProtectedPaths()).Select(KnownPaths.Long).ToList();
        Mode = mode;
        _log = log;
    }

    /// <summary>The app's own data (logs, backups) is never cleaned.</summary>
    public static IEnumerable<string> DefaultProtectedPaths() =>
    [
        Path.Combine(KnownPaths.LocalAppData, "WinCleaner"),
        Path.Combine(KnownPaths.ProgramData, "WinCleaner"),
    ];

    /// <summary>Checks a path without changing anything.</summary>
    public RemovalError? Validate(string path)
    {
        var outcome = Process(path, RemovalMode.DryRun, bins: null, measure: false, CancellationToken.None);
        return outcome.Error;
    }

    /// <summary>Removes the given items and returns one outcome per item.</summary>
    public IReadOnlyList<RemovalOutcome> Remove(IEnumerable<string> paths, IProgress<RemovalOutcome>? progress = null,
        CancellationToken cancellation = default)
    {
        var outcomes = new List<RemovalOutcome>();
        var bins = new Dictionary<char, SafeFileHandle?>();
        try
        {
            foreach (var path in paths)
            {
                cancellation.ThrowIfCancellationRequested();
                var outcome = Process(path, Mode, bins, measure: true, cancellation);
                _log?.Record(Mode, outcome);
                outcomes.Add(outcome);
                progress?.Report(outcome);
            }
        }
        finally
        {
            foreach (var bin in bins.Values) bin?.Dispose();
        }
        return outcomes;
    }

    /// <summary>The allowed root that strictly contains <paramref name="path"/>, preferring the deepest.</summary>
    public string? RootFor(string path) =>
        AllowedRoots.Where(r => PathGuard.IsStrictlyInside(path, r)).OrderByDescending(r => r.Length).FirstOrDefault()
        ?? ItemParentFor(path);

    /// <summary>The parent folder when <paramref name="path"/> is one of the allowed single items.</summary>
    private string? ItemParentFor(string path)
    {
        string? parent = Path.GetDirectoryName(path);
        string name = Path.GetFileName(path);
        if (parent is null) return null;
        foreach (var pattern in AllowedItems)
        {
            string? patternParent = Path.GetDirectoryName(pattern);
            if (patternParent is not null && string.Equals(patternParent, parent, StringComparison.OrdinalIgnoreCase)
                && FileWalker.Matches(name, Path.GetFileName(pattern)))
                return parent;
        }
        return null;
    }

    /// <summary>
    /// Moves one item into an already open folder (same volume) under a new
    /// name, with the same checks as a removal: inside an allowed root, no
    /// reparse point on the way, not TrustedInstaller's, not WRP. Nothing is
    /// ever replaced. Used by the quarantine.
    /// </summary>
    public RemovalOutcome MoveInto(string path, SafeFileHandle destination, string newName)
    {
        RemovalOutcome Fail(RemovalError error, string? message = null) => new(path, 0, error, message);
        if (!PathGuard.TrySplit(path, out _, out var components) || components.Length == 0) return Fail(RemovalError.InvalidPath);
        if (AllowedRoots.Any(r => string.Equals(r, path, StringComparison.OrdinalIgnoreCase))) return Fail(RemovalError.IsAllowedRoot);
        string? root = RootFor(path);
        if (root is null) return Fail(RemovalError.OutsideAllowedRoots);
        if (ProtectedPaths.Any(p => PathGuard.IsSameOrInside(p, path) || PathGuard.IsSameOrInside(path, p))) return Fail(RemovalError.SystemProtected);
        var relative = PathGuard.RelativeComponents(path, root);
        try
        {
            using var rootHandle = PinnedFileSystem.OpenDirectoryPath(root);
            using var parent = PinnedFileSystem.OpenPath(rootHandle, relative[..^1]);
            using var item = PinnedFileSystem.OpenRelative(parent, relative[^1], HandleTree.ItemAccess);
            if (PinnedFileSystem.IsOwnedByTrustedInstaller(item)) return Fail(RemovalError.SystemProtected, "TrustedInstaller");
            var info = PinnedFileSystem.GetInfo(item);
            if (!info.IsDirectory && IsWindowsProtected(path)) return Fail(RemovalError.SystemProtected, "WRP");
            if (Mode == RemovalMode.DryRun) return new RemovalOutcome(path, 0, null);
            long size = HandleTree.Measure(item, CancellationToken.None);
            PinnedFileSystem.Rename(item, destination, newName);
            var outcome = new RemovalOutcome(path, size, null, newName);
            _log?.Write($"quarantine\tOK {size}\t{path}");
            return outcome;
        }
        catch (ReparsePointException e) { return Fail(RemovalError.ReparsePointInPath, e.Message); }
        catch (FileSystemException e) when (e.IsNotFound) { return Fail(RemovalError.NotFound); }
        catch (FileSystemException e) when (e.IsInUse) { return Fail(RemovalError.InUse, e.Message); }
        catch (FileSystemException e) when (e.IsAccessDenied) { return Fail(RemovalError.AccessDenied, e.Message); }
        catch (FileSystemException e) { return Fail(RemovalError.Failed, e.Message); }
    }

    private RemovalOutcome Process(string path, RemovalMode mode, Dictionary<char, SafeFileHandle?>? bins,
        bool measure, CancellationToken cancellation)
    {
        RemovalOutcome Fail(RemovalError error, string? message = null, long freed = 0, int inUse = 0) =>
            new(path, freed, error, message, inUse);

        if (!PathGuard.TrySplit(path, out string drive, out var components) || components.Length == 0)
            return Fail(RemovalError.InvalidPath);
        if (AllowedRoots.Any(r => string.Equals(r, path, StringComparison.OrdinalIgnoreCase)))
            return Fail(RemovalError.IsAllowedRoot);
        string? root = RootFor(path);
        if (root is null) return Fail(RemovalError.OutsideAllowedRoots);
        if (ProtectedPaths.Any(p => PathGuard.IsSameOrInside(p, path) || PathGuard.IsSameOrInside(path, p)))
            return Fail(RemovalError.SystemProtected);

        var relative = PathGuard.RelativeComponents(path, root);
        try
        {
            using var rootHandle = PinnedFileSystem.OpenDirectoryPath(root);
            using var parent = PinnedFileSystem.OpenPath(rootHandle, relative[..^1]);
            using var item = PinnedFileSystem.OpenRelative(parent, relative[^1], HandleTree.ItemAccess);

            if (PinnedFileSystem.IsOwnedByTrustedInstaller(item)) return Fail(RemovalError.SystemProtected, "TrustedInstaller");
            var info = PinnedFileSystem.GetInfo(item);
            if (!info.IsDirectory && IsWindowsProtected(path)) return Fail(RemovalError.SystemProtected, "WRP");

            switch (mode)
            {
                case RemovalMode.DryRun:
                    return new RemovalOutcome(path, measure ? HandleTree.Measure(item, cancellation) : 0, null);

                case RemovalMode.Delete:
                {
                    var stats = new TreeStats();
                    HandleTree.DeleteOpened(item, stats, 0, cancellation);
                    if (stats.Removed == 0 && stats.InUse > 0) return Fail(RemovalError.InUse, null, stats.Bytes, stats.InUse);
                    if (stats.Removed == 0 && stats.Failed > 0) return Fail(RemovalError.Failed, stats.FirstError);
                    return new RemovalOutcome(path, stats.Bytes, null, stats.FirstError, stats.InUse + stats.Failed);
                }

                case RemovalMode.Recycle:
                {
                    char letter = drive[0];
                    if (bins is null) return Fail(RemovalError.RecycleBinUnavailable);
                    if (!bins.TryGetValue(letter, out var bin))
                    {
                        bin = RecycleBin.OpenOrCreate(letter);
                        bins[letter] = bin;
                    }
                    if (bin is null) return Fail(RemovalError.RecycleBinUnavailable);
                    long size = HandleTree.Measure(item, cancellation);
                    RecycleBin.Move(bin, letter, item, path, size);
                    return new RemovalOutcome(path, size, null);
                }
            }
            return Fail(RemovalError.Failed, "Unknown mode");
        }
        catch (ReparsePointException e) { return Fail(RemovalError.ReparsePointInPath, e.Message); }
        catch (FileSystemException e) when (e.IsNotFound) { return Fail(RemovalError.NotFound); }
        catch (FileSystemException e) when (e.IsInUse) { return Fail(RemovalError.InUse, e.Message); }
        catch (FileSystemException e) when (e.IsAccessDenied)
        {
            // Renaming a folder fails with "access denied" while a file inside it is open.
            return Fail(mode == RemovalMode.Recycle ? RemovalError.InUse : RemovalError.AccessDenied, e.Message);
        }
        catch (FileSystemException e) when (e.Win32Error == ERROR_NOT_SAME_DEVICE)
        {
            return Fail(RemovalError.RecycleBinUnavailable, e.Message);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return Fail(RemovalError.Failed, e.Message);
        }
    }

    /// <summary>Windows Resource Protection (system files that SFC restores).</summary>
    public static bool IsWindowsProtected(string path)
    {
        try { return SfcIsFileProtected(IntPtr.Zero, path); }
        catch (DllNotFoundException) { return false; }
        catch (EntryPointNotFoundException) { return false; }
    }
}
