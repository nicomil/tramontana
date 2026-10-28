using System.Numerics;
using System.Security.Cryptography;
using Windows.Graphics.Imaging;
using Tramontana.Core;

namespace Tramontana.Modules;

/// <summary>Big files in the user's folders, grouped by kind, plus old downloads. Nothing is preselected.</summary>
public sealed class LargeOldFilesModule : ICleanerModule
{
    public string Id => "large-old-files";
    public string Title => "File grandi e vecchi";
    public long MinimumSize { get; set; } = 50_000_000;
    public int OldDownloadDays { get; set; } = 90;

    public IReadOnlyList<string> AllowedRoots => Roots.UserFiles();

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        string downloads = KnownPaths.Downloads;
        var oldLimit = DateTime.UtcNow.AddDays(-OldDownloadDays);
        var oldDownloads = new List<ScanItem>();
        var byKind = new Dictionary<FileKind, List<ScanItem>>();

        progress?.Report("Ricerca dei file grandi…");
        foreach (var file in UserFilesWalker.Walk(AllowedRoots, 1_000_000, cancellation))
        {
            string detail = $"Modificato {UserFilesWalker.Age(file.LastWriteUtc)} · {Path.GetDirectoryName(file.Path)}";
            if (PathGuard.IsStrictlyInside(file.Path, downloads) && file.LastUsedUtc < oldLimit)
            {
                oldDownloads.Add(new ScanItem(file.Path, file.Size, RiskLevel.Medium, false, false, detail, file.LastWriteUtc));
            }
            else if (file.Size >= MinimumSize)
            {
                var kind = FileKinds.Of(file.Path);
                if (!byKind.TryGetValue(kind, out var list)) byKind[kind] = list = [];
                list.Add(new ScanItem(file.Path, file.Size, RiskLevel.High, false, false, detail, file.LastWriteUtc));
            }
        }

        var categories = new List<ScanCategory>();
        if (oldDownloads.Count > 0)
            categories.Add(new ScanCategory("old-downloads", $"Download non usati da {OldDownloadDays} giorni",
                [.. oldDownloads.OrderByDescending(i => i.Size)]) { Group = "downloads" });
        foreach (var kind in Enum.GetValues<FileKind>())
        {
            if (!byKind.TryGetValue(kind, out var items)) continue;
            categories.Add(new ScanCategory($"large-{kind.ToString().ToLowerInvariant()}", $"{kind.Title()} grandi",
                [.. items.OrderByDescending(i => i.Size)]) { Group = "large" });
        }
        return new ScanReport(Id, categories);
    }, cancellation);
}

/// <summary>
/// Exact duplicate files in the user's folders. Files are grouped by size,
/// then by a hash of their first and last 64 KB, and only the remaining
/// candidates get a full SHA-256. Hard links of the same file are not
/// duplicates. In each group one copy is kept: the one not in Downloads, then
/// the most recently changed. Only copies in Downloads are preselected.
/// </summary>
public sealed class DuplicatesModule : ICleanerModule
{
    public string Id => "duplicates";
    public string Title => "Duplicati";
    public long MinimumSize { get; set; } = 1_000_000;
    private readonly IReadOnlyList<string>? _roots;
    private readonly string _downloads;

    public DuplicatesModule(IReadOnlyList<string>? roots = null, string? downloads = null)
    {
        _roots = roots;
        _downloads = downloads ?? KnownPaths.Downloads;
    }

    public IReadOnlyList<string> AllowedRoots => _roots ?? Roots.UserFiles();

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(() =>
    {
        progress?.Report("Raccolta dei file…");
        var bySize = UserFilesWalker.Walk(AllowedRoots, MinimumSize, cancellation)
            .GroupBy(f => f.Size).Where(g => g.Count() > 1).Select(g => g.ToList()).ToList();

        progress?.Report("Confronto del contenuto…");
        var groups = new List<List<FileRecord>>();
        var gate = new object();
        Parallel.ForEach(bySize, new ParallelOptions { MaxDegreeOfParallelism = 3, CancellationToken = cancellation }, files =>
        {
            var distinct = UniqueByFileId(files);
            if (distinct.Count < 2) return;
            foreach (var partial in GroupBy(distinct, f => PartialHash(f.Path)).Where(g => g.Count > 1))
            foreach (var full in GroupBy(partial, f => FullHash(f.Path, cancellation)).Where(g => g.Count > 1))
                lock (gate) groups.Add(full);
        });

        var categories = groups.Select(files =>
        {
            var keep = CopyToKeep(files, _downloads);
            var items = files.Select(f =>
            {
                bool kept = f.Path == keep.Path;
                bool inDownloads = PathGuard.IsStrictlyInside(f.Path, _downloads);
                return new ScanItem(f.Path, f.Size, RiskLevel.Medium, !kept && inDownloads, false,
                    kept ? "Copia da tenere" : Path.GetDirectoryName(f.Path), f.LastWriteUtc);
            }).ToList();
            return new ScanCategory($"dup-{keep.Path}", $"{Path.GetFileName(keep.Path)} · {files.Count} copie", items)
            {
                Keep = keep.Path,
                Group = "duplicates",
            };
        }).OrderByDescending(c => c.TotalSize - c.Items.First(i => i.Path == c.Keep).Size).ToList();
        return new ScanReport(Id, categories);
    }, cancellation);

    /// <summary>
    /// Checked again right before cleaning: the copy that stays must still
    /// exist and still have the same content as every copy being removed.
    /// </summary>
    public static bool StillDuplicates(IEnumerable<string> paths, string keep)
    {
        var reference = FullHash(keep, CancellationToken.None);
        if (reference is null) return false;
        return paths.All(p => !string.Equals(p, keep, StringComparison.OrdinalIgnoreCase) && FullHash(p, CancellationToken.None) == reference);
    }

    internal static FileRecord CopyToKeep(List<FileRecord> files, string downloads) =>
        files.OrderBy(f => PathGuard.IsStrictlyInside(f.Path, downloads) ? 1 : 0)
             .ThenByDescending(f => f.LastWriteUtc).First();

    private static List<FileRecord> UniqueByFileId(List<FileRecord> files)
    {
        var seen = new HashSet<(ulong, UInt128)>();
        var result = new List<FileRecord>();
        foreach (var f in files)
        {
            try
            {
                using var handle = File.OpenHandle(f.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (seen.Add(PinnedFileSystem.GetFileId(handle))) result.Add(f);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return result;
    }

    private static List<List<FileRecord>> GroupBy(List<FileRecord> files, Func<FileRecord, string?> hash)
    {
        var buckets = new Dictionary<string, List<FileRecord>>();
        foreach (var f in files)
        {
            if (hash(f) is not { } key) continue;
            if (!buckets.TryGetValue(key, out var list)) buckets[key] = list = [];
            list.Add(f);
        }
        return [.. buckets.Values];
    }

    private const int Chunk = 64 * 1024;

    internal static string? PartialHash(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            long length = RandomAccess.GetLength(handle);
            var buffer = new byte[Chunk];
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int read = RandomAccess.Read(handle, buffer, 0);
            hash.AppendData(buffer, 0, read);
            if (length > Chunk * 2)
            {
                read = RandomAccess.Read(handle, buffer, length - Chunk);
                hash.AppendData(buffer, 0, read);
            }
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    internal static string? FullHash(string path, CancellationToken cancellation)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1 << 20];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (cancellation.IsCancellationRequested) return null;
                hash.AppendData(buffer, 0, read);
            }
            return Convert.ToHexString(hash.GetHashAndReset());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}

/// <summary>
/// Photos that look alike (the same shot saved twice, resized copies, bursts).
/// Each image gets a 64-bit difference hash from a 9×8 grayscale thumbnail
/// decoded by Windows; images within <see cref="MaxDistance"/> bits are
/// grouped and the biggest is kept. Similar is not identical: nothing is
/// preselected.
/// </summary>
public sealed class SimilarImagesModule : ICleanerModule
{
    public string Id => "similar-images";
    public string Title => "Immagini simili";
    public int MaxDistance { get; set; } = 5;
    private readonly IReadOnlyList<string>? _roots;

    public SimilarImagesModule(IReadOnlyList<string>? roots = null) => _roots = roots;

    public IReadOnlyList<string> AllowedRoots => _roots ?? Roots.UserFiles();

    private static readonly HashSet<string> Decodable = new(StringComparer.OrdinalIgnoreCase)
        { ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".heic", ".heif", ".webp", ".jxr", ".avif" };

    private sealed record Entry(FileRecord File, ulong Hash, long Pixels);

    public Task<ScanReport> ScanAsync(IProgress<string>? progress, CancellationToken cancellation) => Task.Run(async () =>
    {
        progress?.Report("Ricerca delle immagini…");
        var files = UserFilesWalker.Walk(AllowedRoots, 30_000, cancellation)
            .Where(f => Decodable.Contains(Path.GetExtension(f.Path))).ToList();
        var entries = new System.Collections.Concurrent.ConcurrentBag<Entry>();
        int done = 0;
        await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount, CancellationToken = cancellation },
            async (file, token) =>
            {
                var result = await DifferenceHash(file.Path);
                // Flat images (all one colour) all hash alike: skip them.
                if (result is { } r && r.Hash != 0 && r.Hash != ulong.MaxValue) entries.Add(new Entry(file, r.Hash, r.Pixels));
                int n = Interlocked.Increment(ref done);
                if (n % 50 == 0) progress?.Report($"Immagini analizzate: {n} di {files.Count}");
            });

        var list = entries.ToList();
        var groups = Cluster(list.Select(e => e.Hash).ToList(), MaxDistance);
        var categories = groups.Select(indices =>
        {
            var members = indices.Select(i => list[i]).ToList();
            var keep = members.OrderByDescending(m => m.Pixels).ThenByDescending(m => m.File.Size).First();
            var items = members.Select(m => new ScanItem(m.File.Path, m.File.Size, RiskLevel.Medium, false, false,
                m.File.Path == keep.File.Path ? "Migliore (risoluzione più alta)" : Path.GetDirectoryName(m.File.Path),
                m.File.LastWriteUtc)).ToList();
            return new ScanCategory($"similar-{keep.File.Path}", $"{Path.GetFileName(keep.File.Path)} · {members.Count} simili", items)
            {
                Keep = keep.File.Path,
                Group = "similar",
            };
        }).OrderByDescending(c => c.TotalSize).ToList();
        return new ScanReport(Id, categories);
    }, cancellation);

    /// <summary>Groups hashes within <paramref name="maxDistance"/> bits of each other (union-find).</summary>
    internal static List<List<int>> Cluster(IReadOnlyList<ulong> hashes, int maxDistance)
    {
        var parent = Enumerable.Range(0, hashes.Count).ToArray();
        int Find(int i)
        {
            while (parent[i] != i) { parent[i] = parent[parent[i]]; i = parent[i]; }
            return i;
        }
        for (int i = 0; i < hashes.Count; i++)
            for (int j = i + 1; j < hashes.Count; j++)
                if (BitOperations.PopCount(hashes[i] ^ hashes[j]) <= maxDistance)
                    parent[Find(i)] = Find(j);
        return Enumerable.Range(0, hashes.Count).GroupBy(Find).Where(g => g.Count() > 1).Select(g => g.ToList()).ToList();
    }

    internal static async Task<(ulong Hash, long Pixels)?> DifferenceHash(string path)
    {
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.Asynchronous);
            using var random = stream.AsRandomAccessStream();
            var decoder = await BitmapDecoder.CreateAsync(random);
            var transform = new BitmapTransform { ScaledWidth = 9, ScaledHeight = 8, InterpolationMode = BitmapInterpolationMode.Fant };
            var data = await decoder.GetPixelDataAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Ignore, transform,
                ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
            var pixels = data.DetachPixelData();
            if (pixels.Length < 9 * 8 * 4) return null;
            Span<int> gray = stackalloc int[72];
            for (int i = 0; i < 72; i++)
                gray[i] = pixels[i * 4 + 2] * 299 + pixels[i * 4 + 1] * 587 + pixels[i * 4] * 114;
            ulong hash = 0;
            for (int row = 0; row < 8; row++)
                for (int col = 0; col < 8; col++)
                {
                    hash <<= 1;
                    if (gray[row * 9 + col] > gray[row * 9 + col + 1]) hash |= 1;
                }
            return (hash, (long)decoder.OrientedPixelWidth * decoder.OrientedPixelHeight);
        }
        catch (Exception)
        {
            // Unsupported or damaged image.
            return null;
        }
    }
}
