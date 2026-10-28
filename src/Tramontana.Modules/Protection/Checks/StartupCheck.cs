using Tramontana.Modules.Performance;

namespace Tramontana.Modules.Protection.Checks;

/// <summary>Run keys, Startup folders, scheduled tasks and services, judged by <see cref="StartupAssessor"/>.</summary>
public sealed class StartupCheck : IProtectionCheck
{
    public string Id => "startup";
    public string Title => "Avvio automatico";

    public IEnumerable<Finding> Run(CheckContext context)
    {
        foreach (var item in context.Startup)
        {
            if (StartupAssessor.Assess(item, context.Signatures, context.UserProfile, context.TrustedPublishers) is not { } verdict) continue;
            bool disableable = item.Kind is StartupKind.RunKey or StartupKind.StartupFolder or StartupKind.ScheduledTask or StartupKind.Service;
            yield return new Finding($"startup|{item.Id}", Categories.Startup, item.Name, verdict.Reason, verdict.Severity)
            {
                Path = item.Executable,
                Startup = item,
                Evidence = verdict.Evidence,
                Publisher = verdict.Publisher,
                Action = disableable && item.Enabled ? FindingAction.DisableStartup : FindingAction.None,
            };
        }
    }
}
