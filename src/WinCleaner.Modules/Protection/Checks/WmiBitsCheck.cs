namespace WinCleaner.Modules.Protection.Checks;

/// <summary>
/// Fileless persistence: WMI event subscriptions that run a command when
/// something happens (a classic that survives reinstalls of the program),
/// and BITS jobs that download or run things in the background.
/// </summary>
public sealed class WmiBitsCheck : IProtectionCheck
{
    public string Id => "wmi-bits";
    public string Title => "Sottoscrizioni WMI e lavori BITS";

    public const string Scope = @"root\subscription";
    public const string FiltersQuery = "SELECT Name, Query FROM __EventFilter";
    public const string CommandConsumersQuery = "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer";
    public const string ScriptConsumersQuery = "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer";
    public const string BindingsQuery = "SELECT Filter, Consumer FROM __FilterToConsumerBinding";

    /// <summary>Subscriptions Windows itself ships.</summary>
    private static readonly string[] KnownConsumers = ["SCM Event Log Consumer", "BVTConsumer"];

    public IEnumerable<Finding> Run(CheckContext context)
    {
        var list = new List<Finding>();
        var consumers = new List<(string Name, string Kind, string Command)>();
        foreach (var c in context.Wmi.Query(Scope, CommandConsumersQuery))
            consumers.Add((c.GetValueOrDefault("Name") as string ?? "?", "comando", (c.GetValueOrDefault("CommandLineTemplate") ?? c.GetValueOrDefault("ExecutablePath")) as string ?? ""));
        foreach (var c in context.Wmi.Query(Scope, ScriptConsumersQuery))
            consumers.Add((c.GetValueOrDefault("Name") as string ?? "?", "script " + (c.GetValueOrDefault("ScriptingEngine") as string ?? ""),
                (c.GetValueOrDefault("ScriptText") ?? c.GetValueOrDefault("ScriptFileName")) as string ?? ""));
        var filters = context.Wmi.Query(Scope, FiltersQuery).ToDictionary(f => f.GetValueOrDefault("Name") as string ?? "?", f => f.GetValueOrDefault("Query") as string ?? "", StringComparer.OrdinalIgnoreCase);
        var bindings = context.Wmi.Query(Scope, BindingsQuery).Select(b => (Filter: Ref(b.GetValueOrDefault("Filter")), Consumer: Ref(b.GetValueOrDefault("Consumer")))).ToList();
        if (context.Evidence?["wmi-subscriptions"] is { } section)
        {
            // One line per item: consumer|name|kind|command  or  filter|name|query  or  binding|filter|consumer
            foreach (var raw in section.Split('\n'))
            {
                var parts = raw.TrimEnd('\r').Split('|', 4);
                if (parts.Length >= 4 && parts[0] == "consumer" && !consumers.Any(c => c.Name.Equals(parts[1], StringComparison.OrdinalIgnoreCase))) consumers.Add((parts[1], parts[2], parts[3]));
                else if (parts.Length >= 3 && parts[0] == "filter") filters.TryAdd(parts[1], string.Join('|', parts.Skip(2)));
                else if (parts.Length >= 3 && parts[0] == "binding") bindings.Add((parts[1], parts[2]));
            }
        }
        foreach (var (name, kind, command) in consumers)
        {
            if (KnownConsumers.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            var filterName = bindings.FirstOrDefault(b => b.Consumer.Equals(name, StringComparison.OrdinalIgnoreCase)).Filter;
            var query = filterName is not null && filters.TryGetValue(filterName, out var q) ? q : null;
            var reasons = Suspicion.CommandLineReasons(command);
            list.Add(new Finding($"wmi|{name}", Categories.Persistence, $"Sottoscrizione WMI: {name}",
                "Un comando parte da solo quando accade un evento di sistema (ad esempio ogni accesso). Nessun programma normale lo fa: è persistenza senza file."
                + (reasons.Count > 0 ? " " + string.Join(". ", reasons) + "." : ""), Severity.Danger)
            { Evidence = [$"Tipo: {kind}", $"Comando: {command}", $"Filtro: {filterName ?? "?"}", $"Evento: {query ?? "?"}"] });
        }

        // BITS jobs: the user's own without privileges, every user's from the evidence.
        string bits = context.Commands.Run("bitsadmin.exe", "/list", "/verbose") + "\n" + (context.Evidence?["bits"] ?? "");
        foreach (var job in ParseBits(bits))
        {
            bool runs = job.Notify.Length > 0;
            bool rawUrl = job.Urls.Any(u => System.Text.RegularExpressions.Regex.IsMatch(u, @"^https?://\d+\.\d+\.\d+\.\d+"));
            if (!runs && !rawUrl && !job.Urls.Any()) continue;
            list.Add(new Finding($"bits|{job.Id}", Categories.Persistence, $"Lavoro BITS: {job.Name}",
                runs ? $"Al termine del trasferimento esegue «{job.Notify}»: tecnica usata per riavviare un malware dopo la pulizia."
                     : rawUrl ? "Scarica da un indirizzo IP grezzo invece che da un nome: raro per un aggiornamento legittimo."
                     : "Trasferimento in background da parte di un programma: controlla la fonte.",
                runs || rawUrl ? Severity.Danger : Severity.Info)
            { Evidence = [$"GUID {job.Id}", $"Stato: {job.State}", .. job.Urls.Take(5).Select(u => "URL: " + u), runs ? $"Comando: {job.Notify}" : ""] });
        }
        return list;
    }

    private static string Ref(object? value)
    {
        // "__EventFilter.Name=\"X\"" → X
        var s = value as string ?? "";
        int eq = s.IndexOf('=');
        return eq < 0 ? s : s[(eq + 1)..].Trim('"');
    }

    public sealed record BitsJob(string Id, string Name, string State, string Notify, List<string> Urls);

    /// <summary>`bitsadmin /list /verbose`: "GUID: {…} DISPLAY: name" blocks with STATE, NOTIFICATION COMMAND LINE and REMOTE NAME lines.</summary>
    internal static List<BitsJob> ParseBits(string text)
    {
        var jobs = new List<BitsJob>();
        BitsJob? current = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var guid = System.Text.RegularExpressions.Regex.Match(line, @"^GUID:\s*(\{[0-9A-Fa-f-]+\})\s*DISPLAY:\s*(.*)$");
            if (guid.Success)
            {
                current = new BitsJob(guid.Groups[1].Value, guid.Groups[2].Value.Trim(), "", "", []);
                jobs.Add(current);
                continue;
            }
            if (current is null) continue;
            if (line.StartsWith("STATE:", StringComparison.OrdinalIgnoreCase))
            {
                var state = line[6..].Trim().Split(' ')[0];
                jobs[^1] = current = current with { State = state };
            }
            else if (line.StartsWith("NOTIFICATION COMMAND LINE:", StringComparison.OrdinalIgnoreCase))
            {
                var command = line[26..].Trim();
                if (!command.Equals("none", StringComparison.OrdinalIgnoreCase) && command.Length > 0) jobs[^1] = current = current with { Notify = command };
            }
            else if (line.Contains("REMOTE NAME", StringComparison.OrdinalIgnoreCase) || System.Text.RegularExpressions.Regex.IsMatch(line, @"^\d+ / \S+ WORKING|^https?://"))
            {
                var url = System.Text.RegularExpressions.Regex.Match(line, @"https?://\S+");
                if (url.Success) current.Urls.Add(url.Value);
            }
        }
        return jobs;
    }
}
