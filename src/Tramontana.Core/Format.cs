using System.Globalization;

namespace Tramontana.Core;

/// <summary>Sizes and dates as shown to the user (Italian).</summary>
public static class Format
{
    private static readonly CultureInfo Italian = CultureInfo.GetCultureInfo("it-IT");

    /// <summary>Decimal units, like Explorer's "size on disk" but with one decimal: 1,5 GB.</summary>
    public static string Bytes(long bytes)
    {
        if (bytes <= 0) return "0 KB";
        string[] units = ["byte", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1000 && unit < units.Length - 1) { value /= 1000; unit++; }
        if (unit == 0) return $"{bytes} byte";
        return value.ToString(value >= 100 ? "0" : "0.#", Italian) + " " + units[unit];
    }
}
