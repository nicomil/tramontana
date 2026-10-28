using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Tramontana.Core;

namespace Tramontana.App.Services;

/// <summary>Minimal INotifyPropertyChanged base for the view models.</summary>
public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>User preferences, in %LOCALAPPDATA%\Tramontana\settings.json.</summary>
public sealed class Settings
{
    public RemovalMode DefaultMode { get; set; } = RemovalMode.Recycle;
    public int LargeFileMegabytes { get; set; } = 50;
    /// <summary>never, daily or weekly.</summary>
    public string Schedule { get; set; } = "never";
    public bool TrayIcon { get; set; } = true;
    public bool CloseToTray { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool WelcomeShown { get; set; }
    public bool RestorePointBeforeRegistry { get; set; } = true;
    public List<string> IgnoredFindings { get; set; } = [];
    /// <summary>Signers the user trusts: their warnings are hidden in Protection.</summary>
    public List<string> TrustedPublishers { get; set; } = [];
    public DateTime? LastHealthCheck { get; set; }

    private static readonly string FilePath = Path.Combine(DataFolders.Root, "settings.json");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath)) return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath), Json) ?? new Settings();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
        return new Settings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Json));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>Opening things in Windows: folders, files, settings pages, the Recycle Bin.</summary>
public static class Shell
{
    public static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    /// <summary>Opens Explorer with the item selected.</summary>
    public static void Reveal(string path)
    {
        try
        {
            var info = new ProcessStartInfo(Path.Combine(KnownPaths.Windows, "explorer.exe")) { UseShellExecute = false };
            if (File.Exists(path) || Directory.Exists(path)) info.ArgumentList.Add("/select," + path);
            else if (Path.GetDirectoryName(path) is { } parent && Directory.Exists(parent)) info.ArgumentList.Add(parent);
            Process.Start(info);
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    public static void OpenRecycleBin() => Open("shell:RecycleBinFolder");

    public static void OpenRegistryKey(string key)
    {
        // regedit opens at the last key it remembers.
        using var applet = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
        applet.SetValue("LastKey", "Computer\\" + key);
        Open(Path.Combine(KnownPaths.Windows, "regedit.exe"));
    }
}

/// <summary>Content dialogs with the window's XamlRoot.</summary>
public static class Dialogs
{
    /// <summary>
    /// Read when needed: the window's content gets its XamlRoot only once it
    /// is in the visual tree, which can be after the first Activated event.
    /// </summary>
    public static XamlRoot? Root => App.Window?.Content?.XamlRoot;

    public static async Task<bool> ConfirmAsync(string title, string message, string primary, bool destructive = false)
    {
        if (Root is null)
        {
            OperationLog.Standard.Write($"app\tdialog without XamlRoot\t{title}");
            return false;
        }
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = primary,
            CloseButtonText = "Annulla",
            DefaultButton = destructive ? ContentDialogButton.Close : ContentDialogButton.Primary,
            XamlRoot = Root,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    public static async Task InfoAsync(string title, string message)
    {
        if (Root is null) return;
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "OK",
            XamlRoot = Root,
        };
        await dialog.ShowAsync();
    }

    public static async Task<ContentDialogResult> ShowAsync(ContentDialog dialog)
    {
        if (Root is null) return ContentDialogResult.None;
        dialog.XamlRoot = Root;
        return await dialog.ShowAsync();
    }
}

public static class Text
{
    public static string Mode(RemovalMode mode) => mode switch
    {
        RemovalMode.Recycle => "Sposta nel Cestino",
        RemovalMode.Delete => "Elimina definitivamente",
        _ => "Prova (non rimuove nulla)",
    };

    public static string Error(RemovalError? error) => error switch
    {
        null => "",
        RemovalError.InUse => "in uso da un programma",
        RemovalError.NotFound => "non c'è più",
        RemovalError.AccessDenied => "accesso negato",
        RemovalError.SystemProtected => "protetto da Windows",
        RemovalError.OutsideAllowedRoots => "fuori dalle cartelle consentite",
        RemovalError.ReparsePointInPath => "collegamento nel percorso",
        RemovalError.RecycleBinUnavailable => "Cestino non disponibile su questa unità",
        RemovalError.IsAllowedRoot => "cartella principale",
        RemovalError.InvalidPath => "percorso non valido",
        _ => "non riuscito",
    };

    /// <summary>"Liberati 1,2 GB · 3 elementi in uso lasciati al loro posto".</summary>
    public static string Summary(IReadOnlyCollection<RemovalOutcome> outcomes, RemovalMode mode)
    {
        long freed = outcomes.Sum(o => o.Freed);
        int ok = outcomes.Count(o => o.Succeeded);
        int inUse = outcomes.Sum(o => o.InUse) + outcomes.Count(o => o.Error == RemovalError.InUse);
        int failed = outcomes.Count(o => !o.Succeeded && o.Error is not (RemovalError.InUse or RemovalError.NotFound));
        string verb = mode switch
        {
            RemovalMode.DryRun => "Si libererebbero",
            RemovalMode.Recycle => "Spostati nel Cestino",
            _ => "Liberati",
        };
        var parts = new List<string> { $"{verb} {Format.Bytes(freed)} ({ok} elementi)" };
        if (inUse > 0) parts.Add($"{inUse} in uso lasciati al loro posto");
        if (failed > 0) parts.Add($"{failed} non rimossi");
        return string.Join(" · ", parts);
    }
}
