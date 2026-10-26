using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace WinCleaner.App.Pages;

/// <summary>Small builders shared by the code-built screens.</summary>
internal static class UI
{
    public static Style Style(string key) => (Style)Application.Current.Resources[key];
    public static Brush Brush(string key) => (Brush)Application.Current.Resources[key];

    public static Button Button(string text, RoutedEventHandler click, bool accent = false, string? glyph = null)
    {
        object content = text;
        if (glyph is not null)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            panel.Children.Add(new FontIcon { Glyph = glyph, FontSize = 14 });
            panel.Children.Add(new TextBlock { Text = text });
            content = panel;
        }
        var b = new Button { Content = content };
        if (accent) b.Style = Style("AccentButtonStyle");
        b.Click += click;
        return b;
    }

    public static TextBlock Caption(string text) => new() { Text = text, Style = Style("Caption"), TextTrimming = TextTrimming.CharacterEllipsis };

    public static TextBlock Header(string text) => new() { Text = text, Style = Style("BodyStrongTextBlockStyle"), Margin = new Thickness(8, 12, 0, 4) };

    /// <summary>A list row: optional leading element, title and subtitle, optional trailing elements.</summary>
    public static Grid Row(FrameworkElement? lead, string title, string? subtitle, params FrameworkElement[] trailing)
    {
        var grid = new Grid { ColumnSpacing = 12, Padding = new Thickness(4, 6, 4, 6) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        if (lead is not null) { lead.VerticalAlignment = VerticalAlignment.Center; grid.Children.Add(lead); }
        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = title, TextTrimming = TextTrimming.CharacterEllipsis });
        if (!string.IsNullOrEmpty(subtitle)) texts.Children.Add(Caption(subtitle));
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);
        var right = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
        foreach (var t in trailing) right.Children.Add(t);
        Grid.SetColumn(right, 2);
        grid.Children.Add(right);
        return grid;
    }

    public static void Show(InfoBar bar, string title, string message, InfoBarSeverity severity = InfoBarSeverity.Success)
    {
        bar.Title = title;
        bar.Message = message;
        bar.Severity = severity;
        bar.IsOpen = true;
    }
}
