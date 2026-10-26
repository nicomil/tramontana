using Microsoft.UI.Xaml;

namespace WinCleaner.App.Services;

/// <summary>Helpers for x:Bind function bindings.</summary>
public static class Converters
{
    public static Visibility Visible(bool value) => value ? Visibility.Visible : Visibility.Collapsed;
    public static Visibility Collapsed(bool value) => value ? Visibility.Collapsed : Visibility.Visible;
    public static Visibility VisibleIfText(string? value) => string.IsNullOrEmpty(value) ? Visibility.Collapsed : Visibility.Visible;
    public static bool Not(bool value) => !value;
    public static Visibility VisibleIfAny(int count) => count > 0 ? Visibility.Visible : Visibility.Collapsed;
}

/// <summary>A group of categories for the grouped list ("Windows", "Browser"…).</summary>
public sealed class CategoryGroup(string key, IEnumerable<CategoryViewModel> items) : List<CategoryViewModel>(items)
{
    public string Key { get; } = key;
}
