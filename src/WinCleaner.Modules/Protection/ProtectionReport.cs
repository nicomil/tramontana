using System.Text;

namespace WinCleaner.Modules.Protection;

/// <summary>A Markdown report of the Protection scan, to send to whoever helps from afar.</summary>
public static class ProtectionReport
{
    public static string Markdown(IReadOnlyList<Finding> findings, IReadOnlyCollection<string>? ignored = null, DateTime? date = null, string? host = null)
    {
        var sb = new StringBuilder();
        var when = date ?? DateTime.Now;
        sb.AppendLine($"# Rapporto Protezione · {host ?? Environment.MachineName}");
        sb.AppendLine();
        sb.AppendLine($"Generato da WinCleaner il {when:d MMMM yyyy, HH:mm} · {Environment.OSVersion.VersionString}");
        sb.AppendLine();
        var visible = findings.Where(f => ignored is null || !ignored.Contains(f.Id)).ToList();
        sb.AppendLine("## Riepilogo");
        sb.AppendLine();
        sb.AppendLine($"- Pericoli: {visible.Count(f => f.Severity == Severity.Danger)}");
        sb.AppendLine($"- Avvisi: {visible.Count(f => f.Severity == Severity.Warning)}");
        sb.AppendLine($"- Informazioni: {visible.Count(f => f.Severity == Severity.Info)}");
        sb.AppendLine($"- Nuovi dall'ultimo controllo: {visible.Count(f => f.IsNew)}");
        if (ignored is { Count: > 0 }) sb.AppendLine($"- Ignorati dall'utente: {findings.Count - visible.Count}");
        sb.AppendLine();
        foreach (var category in Categories.Order.Concat(visible.Select(f => f.Category).Distinct()).Distinct())
        {
            var items = visible.Where(f => f.Category == category).OrderByDescending(f => f.Severity).ToList();
            if (items.Count == 0) continue;
            sb.AppendLine($"## {category}");
            sb.AppendLine();
            foreach (var f in items)
            {
                string badge = f.Severity switch { Severity.Danger => "PERICOLO", Severity.Warning => "Avviso", Severity.Info => "Info", _ => "OK" };
                sb.AppendLine($"### {badge}{(f.IsNew ? " · nuovo" : "")}: {f.Title}");
                sb.AppendLine();
                sb.AppendLine($"- {f.Reason}");
                if (f.Path is not null) sb.AppendLine($"- Percorso: `{f.Path}`");
                if (f.Publisher is not null) sb.AppendLine($"- Firmato da: {f.Publisher}");
                if (f.Evidence.Length > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("```");
                    foreach (var line in f.Evidence) sb.AppendLine(line);
                    sb.AppendLine("```");
                }
                sb.AppendLine();
            }
        }
        sb.AppendLine("_Controlli euristici: un avviso non è una prova di malware._");
        return sb.ToString();
    }
}
