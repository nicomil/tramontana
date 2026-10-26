using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;
using WinCleaner.Core;
using WinCleaner.Modules;

namespace WinCleaner.App.Controls;

/// <summary>Squarified treemap of the children of a disk node. Click a folder to open it.</summary>
public sealed partial class Treemap : Grid
{
    private readonly Canvas _canvas = new();
    private DiskNode? _node;

    public event Action<DiskNode>? NodeClicked;
    public event Action<DiskNode, FrameworkElement, Point>? NodeRightClicked;

    public Treemap()
    {
        Children.Add(_canvas);
        SizeChanged += (_, _) => Render();
        Background = new SolidColorBrush(Colors.Transparent);
    }

    /// <summary>Shows the children of a node (a method, not a property, so XAML never tries to create a DiskNode).</summary>
    public void Show(DiskNode? node)
    {
        _node = node;
        Render();
    }

    private static readonly Color[] Palette =
    [
        Color.FromArgb(255, 0x2B, 0x88, 0xD8), Color.FromArgb(255, 0x00, 0x99, 0xBC), Color.FromArgb(255, 0x8E, 0x8C, 0xD8),
        Color.FromArgb(255, 0x00, 0xB2, 0x94), Color.FromArgb(255, 0xE7, 0x48, 0x56), Color.FromArgb(255, 0xF7, 0x63, 0x0C),
        Color.FromArgb(255, 0xCA, 0x50, 0x10), Color.FromArgb(255, 0x88, 0x17, 0x98), Color.FromArgb(255, 0x10, 0x7C, 0x10),
    ];

    private static Color ColorFor(DiskNode node, int index)
    {
        if (node.IsAggregate) return Color.FromArgb(255, 0x7A, 0x7A, 0x7A);
        if (node.IsDirectory) return Palette[index % Palette.Length];
        return FileKinds.Of(node.Path) switch
        {
            FileKind.Video => Color.FromArgb(255, 0xE7, 0x48, 0x56),
            FileKind.Audio => Color.FromArgb(255, 0xF7, 0x63, 0x0C),
            FileKind.Image => Color.FromArgb(255, 0x00, 0xB2, 0x94),
            FileKind.Archive or FileKind.DiskImage => Color.FromArgb(255, 0x8E, 0x8C, 0xD8),
            FileKind.Document => Color.FromArgb(255, 0x00, 0x99, 0xBC),
            _ => Color.FromArgb(255, 0x60, 0x6E, 0x80),
        };
    }

    private void Render()
    {
        _canvas.Children.Clear();
        if (_node is null || ActualWidth < 10 || ActualHeight < 10) return;
        var items = _node.Children.Where(c => c.Size > 0).Take(80).ToList();
        if (items.Count == 0) return;
        var rects = Squarify(items.Select(i => (double)i.Size).ToList(), new Rect(0, 0, ActualWidth, ActualHeight));
        for (int i = 0; i < items.Count; i++)
        {
            var node = items[i];
            var r = rects[i];
            if (r.Width < 2 || r.Height < 2) continue;
            var color = ColorFor(node, i);
            var tile = new Border
            {
                Width = Math.Max(0, r.Width - 2),
                Height = Math.Max(0, r.Height - 2),
                CornerRadius = new CornerRadius(4),
                Background = new SolidColorBrush(color),
                Padding = new Thickness(6, 4, 6, 4),
            };
            if (r.Width > 70 && r.Height > 34)
            {
                var text = new StackPanel();
                text.Children.Add(new TextBlock { Text = node.Name, Foreground = new SolidColorBrush(Colors.White), FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
                text.Children.Add(new TextBlock { Text = Format.Bytes(node.Size), Foreground = new SolidColorBrush(Color.FromArgb(220, 255, 255, 255)), FontSize = 11 });
                tile.Child = text;
            }
            ToolTipService.SetToolTip(tile, $"{node.Name}\n{Format.Bytes(node.Size)}{(node.IsDirectory ? $" · {node.FileCount} file" : "")}");
            tile.PointerEntered += (_, _) => tile.Opacity = 0.85;
            tile.PointerExited += (_, _) => tile.Opacity = 1;
            tile.Tapped += (_, _) => NodeClicked?.Invoke(node);
            tile.RightTapped += (s, e) => NodeRightClicked?.Invoke(node, tile, e.GetPosition(tile));
            Canvas.SetLeft(tile, r.X + 1);
            Canvas.SetTop(tile, r.Y + 1);
            _canvas.Children.Add(tile);
        }
    }

    /// <summary>Squarified layout (Bruls, Huizing, van Wijk): values sorted descending.</summary>
    internal static List<Rect> Squarify(IReadOnlyList<double> values, Rect bounds)
    {
        var result = new Rect[values.Count];
        double total = values.Sum();
        if (total <= 0) return [.. result];
        double scale = bounds.Width * bounds.Height / total;
        var areas = values.Select(v => v * scale).ToList();
        int start = 0;
        var space = bounds;
        while (start < areas.Count)
        {
            double side = Math.Min(space.Width, space.Height);
            int end = start + 1;
            double best = Worst(areas, start, end, side);
            while (end < areas.Count)
            {
                double next = Worst(areas, start, end + 1, side);
                if (next > best) break;
                best = next;
                end++;
            }
            double rowArea = 0;
            for (int i = start; i < end; i++) rowArea += areas[i];
            bool horizontal = space.Width >= space.Height; // lay the row along the short side
            double thickness = rowArea / (horizontal ? space.Height : space.Width);
            double offset = 0;
            for (int i = start; i < end; i++)
            {
                double length = areas[i] / thickness;
                result[i] = horizontal
                    ? new Rect(space.X, space.Y + offset, thickness, length)
                    : new Rect(space.X + offset, space.Y, length, thickness);
                offset += length;
            }
            space = horizontal
                ? new Rect(space.X + thickness, space.Y, Math.Max(0, space.Width - thickness), space.Height)
                : new Rect(space.X, space.Y + thickness, space.Width, Math.Max(0, space.Height - thickness));
            start = end;
        }
        return [.. result];
    }

    private static double Worst(List<double> areas, int start, int end, double side)
    {
        double sum = 0, max = 0, min = double.MaxValue;
        for (int i = start; i < end; i++)
        {
            sum += areas[i];
            max = Math.Max(max, areas[i]);
            min = Math.Min(min, areas[i]);
        }
        double s2 = side * side, sum2 = sum * sum;
        return Math.Max(s2 * max / sum2, sum2 / (s2 * Math.Max(min, 1e-9)));
    }
}
