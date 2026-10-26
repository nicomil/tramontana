using System.Text;

namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Scheduled tasks as the registry sees them, not as Task Scheduler shows
/// them: a task whose security descriptor was deleted does not appear in the
/// console (the trick HAFNIUM used), and the Actions blob says what really
/// runs, LOLBins included, even under \Microsoft\.
/// </summary>
public sealed class HiddenTasksCheck : IProtectionCheck
{
    public string Id => "hidden-tasks";
    public string Title => "Attività pianificate nascoste";

    private const string Cache = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var r = context.Registry;
        var list = new List<Finding>();
        var known = new HashSet<string>(context.Startup.Where(s => s.TaskPath is not null).Select(s => s.TaskPath!), StringComparer.OrdinalIgnoreCase);
        foreach (var id in r.SubKeys($@"{Cache}\Tasks"))
        {
            string key = $@"{Cache}\Tasks\{id}";
            var path = r.GetString(key, "Path");
            if (path is null) continue;
            bool noSd = !r.ValueNames($@"{Cache}\Tree{path}").Contains("SD", StringComparer.OrdinalIgnoreCase);
            bool noTree = !r.KeyExists($@"{Cache}\Tree{path}");
            var actions = r.GetValue(key, "Actions") as byte[];
            var commands = actions is null ? [] : Strings(actions);
            var reasons = commands.SelectMany(Suspicion.CommandLineReasons).Distinct().ToList();
            var author = r.GetString(key, "Author");
            if (noTree || noSd)
            {
                list.Add(new Finding($"hiddentask|{path}", Categories.Persistence, $"Attività pianificata nascosta: {path}",
                    noTree ? "Esiste nel registro ma non nell'albero delle attività: l'Utilità di pianificazione non la mostra."
                           : "Il suo descrittore di sicurezza è stato cancellato: l'Utilità di pianificazione non la mostra più. È una tecnica di occultamento.",
                    Severity.Danger)
                { Path = key, Evidence = [$"Id: {id}", $"Autore: {author ?? "?"}", .. commands.Take(5).Select(c => "Comando: " + c)] });
            }
            else if (reasons.Count > 0 && !(path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) && IsMicrosoftCommand(commands)))
            {
                bool onlyHidden = reasons.All(r => r == "Finestra nascosta");
                list.Add(new Finding($"lolbintask|{path}", Categories.Persistence, $"Attività pianificata sospetta: {path}",
                    string.Join(". ", reasons) + "." + (known.Contains(path) ? "" : " Non compare tra le attività normali."), onlyHidden ? Severity.Warning : Severity.Danger)
                { Path = key, Evidence = [$"Autore: {author ?? "?"}", .. commands.Take(5).Select(c => "Comando: " + c)] });
            }
        }
        return list;
    }

    /// <summary>Every path mentioned by the actions lives under the Windows folder.</summary>
    internal static bool IsMicrosoftCommand(List<string> commands)
    {
        foreach (var command in commands)
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(command, @"(?i)(%[a-z()]+%|[a-z]:)\\[^\s""]*"))
            {
                string p = m.Value;
                bool windows = p.StartsWith("%windir%", StringComparison.OrdinalIgnoreCase) || p.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)
                    || p.StartsWith(Core.KnownPaths.Windows, StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase);
                if (!windows) return false;
            }
        return true;
    }

    /// <summary>UTF-16 strings of at least 4 characters inside the Actions blob.</summary>
    internal static List<string> Strings(byte[] blob)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        for (int i = 0; i + 1 < blob.Length; i += 2)
        {
            char c = (char)(blob[i] | (blob[i + 1] << 8));
            if (c >= 0x20 && c < 0x7F) current.Append(c);
            else
            {
                if (current.Length >= 4) result.Add(current.ToString());
                current.Clear();
            }
        }
        if (current.Length >= 4) result.Add(current.ToString());
        return result;
    }
}
