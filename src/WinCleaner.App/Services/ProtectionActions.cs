using WinCleaner.Core;
using WinCleaner.Modules.Helper;
using WinCleaner.Modules.Performance;
using WinCleaner.Modules.Protection;
using WinCleaner.Modules.Protection.Checks;

namespace WinCleaner.App.Services;

/// <summary>
/// What the Protection screen can do about a finding: the safe removal
/// sequence (stop the process, disable the start-up entry, quarantine the
/// file), registry fixes with a backup, Defender scans, the deep scan with
/// the helper's read-only evidence. Every step reports what it did.
/// </summary>
public static class ProtectionActions
{
    private static AppState S => AppState.Current;

    /// <summary>The root-only facts of the last deep scan, reused by the next scans of this session.</summary>
    public static SystemEvidence? Evidence { get; private set; }
    public static DateTime? DeepScanAt { get; private set; }

    public static async Task<List<Finding>> ScanAsync()
    {
        var evidence = Evidence;
        var findings = await Task.Run(() => ProtectionScanner.Scan(S.Settings.IgnoredFindings, S.Settings.TrustedPublishers, evidence));
        S.Findings = findings;
        return findings;
    }

    /// <summary>One administrator prompt, then the usual scan with the root-only facts added.</summary>
    public static async Task<List<Finding>> DeepScanAsync()
    {
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.CollectSystemEvidence }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error ?? "raccolta non riuscita");
        Evidence = SystemEvidence.Parse(response.Text ?? "");
        DeepScanAt = DateTime.Now;
        return await ScanAsync();
    }

    /// <summary>Stops the process, disables the start-up entry, then puts the file aside. Stops at the first step that fails.</summary>
    public static async Task<string> QuarantineAsync(Finding finding)
    {
        var steps = new List<string>();
        if (finding.ProcessId is { } pid && finding.Action == FindingAction.TerminateProcess)
        {
            await TerminateAsync(pid, finding.Path);
            steps.Add("processo terminato");
        }
        if (finding.Startup is { } startup && startup.Enabled)
        {
            await DisableStartupAsync(startup);
            steps.Add("avvio automatico disattivato");
        }
        if (finding.Path is { } path && File.Exists(path) || finding.Path is { } dir && Directory.Exists(dir))
        {
            string target = finding.Path!;
            if (Suspicion.IsInWindows(target) && !target.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("I file della cartella Windows non vanno in quarantena: usa l'analisi di Defender.");
            var userRoots = Quarantine.UserRoots();
            bool userLevel = userRoots.Any(r => PathGuard.IsStrictlyInside(target, r));
            if (userLevel)
            {
                await Task.Run(() => new Quarantine().Put(target, finding.Title, finding.Reason, userRoots));
            }
            else
            {
                var helper = await S.EnsureHelperAsync();
                var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.Quarantine, Paths = [target], Name = finding.Title, Key = finding.Reason }, CancellationToken.None);
                if (!response.Ok) throw new InvalidOperationException(response.Error);
                var outcome = response.Outcomes.FirstOrDefault();
                if (outcome?.Error is { } error) throw new InvalidOperationException($"{Text.Error(error)} {outcome.Message}");
                var parts = (outcome?.Message ?? "").Split('|');
                if (parts.Length == 3 && Guid.TryParseExact(parts[0], "N", out var id))
                    new Quarantine().Add(new QuarantineRecord(id, finding.Title, KnownPaths.Long(target), finding.Reason, DateTime.Now, parts[1], parts[2], true));
            }
            steps.Add("file in quarantena");
        }
        return steps.Count == 0 ? "Niente da fare" : string.Join(", ", steps);
    }

    public static async Task TerminateAsync(int pid, string? expectedPath)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            string? actual = null;
            try { actual = process.MainModule?.FileName; } catch (Exception) { }
            if (expectedPath is not null && actual is not null && !string.Equals(actual, expectedPath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Il processo non è più quello indicato");
            process.Kill(entireProcessTree: true);
            OperationLog.Standard.Write($"process\tkill\t{pid}\t{actual}");
            return;
        }
        catch (ArgumentException) { return; } // already gone
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            if (expectedPath is null) throw;
        }
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.TerminateProcess, Number = pid, Key = expectedPath }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
    }

    public static async Task DisableStartupAsync(StartupItem item)
    {
        switch (item.Kind)
        {
            case StartupKind.RunKey or StartupKind.StartupFolder when !item.NeedsAdmin:
                StartupManager.SetApproved(item, false);
                break;
            case StartupKind.RunKey or StartupKind.StartupFolder:
            {
                var helper = await S.EnsureHelperAsync();
                var r = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.SetStartupApproved, Key = item.ApprovedKey, Name = item.ValueName, Enabled = false }, CancellationToken.None);
                if (!r.Ok) throw new InvalidOperationException(r.Error);
                break;
            }
            case StartupKind.ScheduledTask:
            {
                try { StartupManager.SetTaskEnabled(item.TaskPath!, false); }
                catch (Exception)
                {
                    var helper = await S.EnsureHelperAsync();
                    var r = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.SetTaskEnabled, Name = item.TaskPath, Enabled = false }, CancellationToken.None);
                    if (!r.Ok) throw new InvalidOperationException(r.Error);
                }
                break;
            }
            case StartupKind.Service:
            {
                var helper = await S.EnsureHelperAsync();
                var r = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.SetServiceStart, Name = item.ServiceName, Number = 4 }, CancellationToken.None);
                if (!r.Ok) throw new InvalidOperationException(r.Error);
                break;
            }
        }
        S.Startup = null;
    }

    /// <summary>Deletes or restores a registry value of the Protection allow list, with a .reg backup.</summary>
    public static async Task<string> RemoveRegistryValueAsync(RegistryTargetInfo target)
    {
        if (!ProtectionRegistry.IsAllowed(target.KeyPath, target.ValueName)) throw new InvalidOperationException("Questa voce non è tra quelle che Protezione può modificare");
        if (!ProtectionRegistry.NeedsAdmin(target.KeyPath))
            return await Task.Run(() => ProtectionRegistry.Apply(target.KeyPath, target.ValueName));
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.RemoveProtectionValue, Key = target.KeyPath, Name = target.ValueName }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
        return response.Text ?? "";
    }

    public static async Task RemoveDefenderExclusionAsync(string kind, string value)
    {
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.RemoveDefenderExclusion, Key = kind, Name = value }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
    }

    public static async Task RemoveWmiSubscriptionAsync(string name)
    {
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.RemoveWmiSubscription, Name = name }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
    }

    public static async Task EnableDefenderRealtimeAsync()
    {
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.EnableDefenderRealtime }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
    }

    public static Task<string> DefenderScanAsync(string path) => ProtectionScanner.DefenderScanPathAsync(path, CancellationToken.None);

    public static async Task RestoreAsync(QuarantineRecord record)
    {
        if (!record.IsSystem) { await Task.Run(() => new Quarantine().Restore(record)); return; }
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.RestoreQuarantined, Name = record.Id.ToString() }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
        new Quarantine().Forget(record);
    }

    public static async Task DeleteAsync(QuarantineRecord record)
    {
        if (!record.IsSystem) { await Task.Run(() => new Quarantine().Delete(record)); return; }
        var helper = await S.EnsureHelperAsync();
        var response = await helper.SendAsync(new HelperRequest { Operation = HelperOperation.DeleteQuarantined, Name = record.Id.ToString() }, CancellationToken.None);
        if (!response.Ok) throw new InvalidOperationException(response.Error);
        new Quarantine().Forget(record);
    }

    /// <summary>Writes the Markdown report where the user chooses.</summary>
    public static async Task<string?> ExportReportAsync(IReadOnlyList<Finding> findings)
    {
        var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = $"Rapporto Protezione {DateTime.Now:yyyy-MM-dd}" };
        picker.FileTypeChoices.Add("Markdown", [".md"]);
        picker.FileTypeChoices.Add("Testo", [".txt"]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.Window!));
        var file = await picker.PickSaveFileAsync();
        if (file is null) return null;
        await File.WriteAllTextAsync(file.Path, ProtectionReport.Markdown(findings, S.Settings.IgnoredFindings));
        return file.Path;
    }

    /// <summary>New findings of the worst kind, for Health Check and the scheduled scan.</summary>
    public static IEnumerable<Finding> NewDangers(IEnumerable<Finding> findings) => findings.Where(f => f.IsNew && f.Severity == Severity.Danger);
}
