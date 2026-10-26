using System.Diagnostics;

namespace WinCleaner.Tests;

/// <summary>A fresh folder under %TEMP% that is removed afterwards, links first.</summary>
public sealed class TempDir : IDisposable
{
    public string Path { get; }

    public TempDir()
    {
        Path = System.IO.Path.Combine(WinCleaner.Core.KnownPaths.Temp, "wctests-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(Path);
    }

    public string Sub(params string[] parts) => System.IO.Path.Combine([Path, .. parts]);

    public string File(string relative, int bytes = 100)
    {
        var full = Sub(relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        System.IO.File.WriteAllBytes(full, new byte[bytes]);
        return full;
    }

    public string Dir(string relative)
    {
        var full = Sub(relative);
        Directory.CreateDirectory(full);
        return full;
    }

    public void Dispose()
    {
        if (!Directory.Exists(Path)) return;
        // Remove links before the recursive delete so it never reaches their targets.
        foreach (var dir in Directory.EnumerateDirectories(Path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).Reverse())
        {
            try
            {
                if (new DirectoryInfo(dir).Attributes.HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(dir);
            }
            catch (IOException) { }
        }
        foreach (var file in Directory.EnumerateFiles(Path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 }))
        {
            try { System.IO.File.SetAttributes(file, FileAttributes.Normal); } catch (IOException) { }
        }
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { }
    }

    /// <summary>Creates a directory junction (no admin rights needed).</summary>
    public static void Junction(string link, string target)
    {
        var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        p.WaitForExit();
        if (!Directory.Exists(link)) throw new InvalidOperationException("mklink /J failed: " + p.StandardError.ReadToEnd());
    }
}
