using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

// Single-process, synthetic incident drill. No model, HTTP, database, or writes
// to external systems. Checks are C# assertions; run with a .NET 10 console app.

// snippet:identities
public sealed record Scope(string Tenant, string Feature);
public sealed record Bundle(string App, string Prompt, string Model,
    string Retrieval, string Index);
public sealed record Policy(string Tenant, string Document, long Version,
    long Revision, string Text, string Group, bool Approved, bool Deleted);
// end:identities

// snippet:controls
public enum ServingMode { Normal, SourcesOnly, Paused }
public sealed record Control(long Revision, ServingMode Mode, Bundle Bundle);
public sealed record RequestContext(string RequestId, Scope Scope,
    string Group, Control StartedWith);
public sealed record Draft(Policy Evidence, Bundle Origin,
    string Text, bool CacheHit);
public sealed record Delivery(string Kind, string Text);
// end:controls

// snippet:receipt
public sealed record AnswerReceipt(string AnswerId, string RequestId, DateTimeOffset CommittedAt,
    Scope Scope, Bundle ExecutingBundle, Bundle OriginBundle,
    string Document, long SourceVersion, long SourceRevision,
    string EvidenceDigest, long ControlRevision, bool CacheHit,
    string Outcome);
// end:receipt

public sealed class IncidentLab
{
    private readonly object sync = new();
    private readonly Dictionary<Scope, Control> controls = new();
    private readonly Dictionary<string, Policy> policies = new();
    private readonly HashSet<(Scope Scope, Bundle Bundle)> quarantine = new();
    private readonly List<AnswerReceipt> receipts = new();
    private static readonly Bundle Unconfigured = new("none", "none", "none", "none", "none");

    private Control Current(Scope scope) => controls.GetValueOrDefault(scope)
        ?? new Control(0, ServingMode.Paused, Unconfigured);

    public Control ReadControl(Scope scope) { lock (sync) return Current(scope); }
    public AnswerReceipt[] ReadReceipts() { lock (sync) return receipts.ToArray(); }

    // Represents an already-authorized catalogue event, effective immediately.
    public void SetPolicy(Policy policy)
    {
        lock (sync)
        {
            if (policies.TryGetValue(policy.Tenant, out var old)
                && policy.Revision <= old.Revision)
                throw new InvalidOperationException("Revision must increase.");
            policies[policy.Tenant] = policy;
        }
    }

    // snippet:change-control
    public bool TryChangeControl(Scope scope, long expectedRevision,
        ServingMode mode, Bundle bundle)
    {
        lock (sync)
        {
            var current = Current(scope);
            if (current.Revision != expectedRevision) return false;
            if (mode == ServingMode.Normal
                && quarantine.Contains((scope, bundle))) return false;
            controls[scope] = new(current.Revision + 1, mode, bundle);
            return true;
        }
    }
    // end:change-control

    // snippet:contain
    public bool Contain(Scope scope, long expectedRevision, Bundle badOrigin)
    {
        lock (sync)
        {
            var current = Current(scope);
            if (current.Revision != expectedRevision) return false;
            quarantine.Add((scope, badOrigin));
            controls[scope] = current with {
                Revision = current.Revision + 1,
                Mode = ServingMode.SourcesOnly
            };
            return true;
        }
    }
    // end:contain

    public RequestContext Begin(string requestId, Scope scope, string group)
    {
        lock (sync) return new(requestId, scope, group, Current(scope));
    }

    // snippet:evidence-check
    private bool Eligible(RequestContext request, Policy evidence) =>
        evidence.Tenant == request.Scope.Tenant
        && policies.TryGetValue(request.Scope.Tenant, out var current)
        && current == evidence && current.Approved && !current.Deleted
        && current.Group == request.Group;
    // end:evidence-check

    // snippet:cache-check
    public bool CanReuse(RequestContext request, Draft cached)
    {
        lock (sync)
        {
            var current = Current(request.Scope);
            return current == request.StartedWith
                && current.Mode == ServingMode.Normal
                && cached.Origin == current.Bundle
                && !quarantine.Contains((request.Scope, cached.Origin))
                && Eligible(request, cached.Evidence);
        }
    }
    // end:cache-check

    // snippet:source-fallback
    public Delivery ReadSources(RequestContext request)
    {
        lock (sync)
        {
            var current = Current(request.Scope);
            if (current != request.StartedWith
                || current.Mode == ServingMode.Paused)
                return new("Blocked", "Policy assistant is temporarily paused.");
            if (!policies.TryGetValue(request.Scope.Tenant, out var source)
                || !Eligible(request, source))
                return new("Unavailable", "Current policy evidence is unavailable.");
            return new("SourcesOnly",
                $"Approved source: {source.Document} v{source.Version}\n{source.Text}");
        }
    }
    // end:source-fallback

    // snippet:commit
    public Delivery Commit(RequestContext request, Draft draft)
    {
        lock (sync)
        {
            var current = Current(request.Scope);
            if (current != request.StartedWith)
                return new("Blocked", "Serving controls changed; request again.");
            if (current.Mode != ServingMode.Normal)
                return new("Blocked", "Generated answers are unavailable.");
            if (draft.Origin != current.Bundle
                || quarantine.Contains((request.Scope, draft.Origin)))
                return new("Blocked", "Answer release is not eligible.");
            if (!Eligible(request, draft.Evidence))
                return new("Blocked", "Answer evidence is no longer eligible.");
            RecordReceipt(request, draft);
            return new("Generated", draft.Text);
        }
    }
    // end:commit

    private void RecordReceipt(RequestContext request, Draft draft)
    {
        var source = draft.Evidence;
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source.Text)));
        receipts.Add(new(Guid.NewGuid().ToString("N"), request.RequestId, DateTimeOffset.UtcNow,
            request.Scope, request.StartedWith.Bundle, draft.Origin,
            source.Document, source.Version, source.Revision, digest,
            request.StartedWith.Revision, draft.CacheHit, "CommittedForDelivery"));
    }
}

public static class TraceExample
{
    private static readonly ActivitySource Source = new("Telemedicine.PolicyAssistant");

    // snippet:trace
    public static Activity? Start(AnswerReceipt receipt)
    {
        var activity = Source.StartActivity("policy.answer");
        activity?.SetTag("app.answer.id", receipt.AnswerId);
        activity?.SetTag("app.request.id", receipt.RequestId);
        activity?.SetTag("app.release.app", receipt.ExecutingBundle.App);
        activity?.SetTag("app.cache.origin.app", receipt.OriginBundle.App);
        activity?.SetTag("app.evidence.revision", receipt.SourceRevision);
        activity?.SetTag("app.control.revision", receipt.ControlRevision);
        return activity;
    }
    // end:trace
}

public static class Investigation
{
    // snippet:impact
    public static AnswerReceipt[] FindCandidates(IEnumerable<AnswerReceipt> receipts,
        Scope scope, Bundle suspect, DateTimeOffset start, DateTimeOffset end) =>
        receipts.Where(r => r.Scope == scope
            && r.CommittedAt >= start && r.CommittedAt < end
            && (r.OriginBundle == suspect || r.ExecutingBundle == suspect))
        .ToArray();
    // end:impact
}

// snippet:recovery-report
public sealed record CheckResult(string Name, bool Passed);
public sealed record RecoveryReport(Bundle Candidate, long EvidenceRevision,
    DateTimeOffset CreatedAt, string Provenance, CheckResult[] Checks);
// end:recovery-report

public static class RecoveryGate
{
    public static readonly string[] Required = [
        "known-bad-answer", "stale-cache", "wrong-tenant",
        "revoked-access", "deleted-source", "in-flight-containment",
        "booking-reconciliation"
    ];

    // snippet:recovery-gate
    public static bool AcceptsLabReport(RecoveryReport report, Bundle candidate,
        long evidenceRevision, DateTimeOffset now)
    {
        var names = report.Checks.Select(x => x.Name).ToArray();
        return report.Provenance == "synthetic-lab"
            && report.Candidate == candidate
            && report.EvidenceRevision == evidenceRevision
            && report.CreatedAt <= now
            && now - report.CreatedAt <= TimeSpan.FromMinutes(30)
            && names.Length == Required.Length
            && names.Distinct(StringComparer.Ordinal).Count() == Required.Length
            && Required.All(name => names.Contains(name, StringComparer.Ordinal))
            && report.Checks.All(x => x.Passed);
    }
    // end:recovery-gate
}

public enum BookingState { Pending, Succeeded, Failed, Unknown }
public sealed record BookingOperation(string Tenant, string Id,
    BookingState State, string? BookingId);

public static class BookingRecovery
{
    // snippet:reconcile
    public static string Explain(BookingOperation? operation) => operation switch
    {
        { State: BookingState.Succeeded, BookingId: { Length: > 0 } id }
            => $"Booking confirmed: {id}.",
        { State: BookingState.Pending } => "Booking is still being checked.",
        { State: BookingState.Failed } => "Booking failed; review the recorded failure.",
        _ => "Booking status needs reconciliation. Do not submit a duplicate."
    };
    // end:reconcile
}

public static class Program
{
    private static int checks;
    private static void Check(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"FAIL: {name}");
        checks++;
        Console.WriteLine($"PASS: {name}");
    }

    public static void Main()
    {
        var lab = new IncidentLab();
        var scope = new Scope("clinic-a", "policy-assistant");
        var other = new Scope("clinic-b", "policy-assistant");
        var v1Bundle = new Bundle("app-1", "prompt-1", "model-1", "retrieval-1", "index-blue");
        var fixedBundle = v1Bundle with { App = "app-2", Retrieval = "retrieval-2" };
        var v1 = new Policy("clinic-a", "cancellation-policy", 1, 1,
            "Specialist cancellations require 48 hours' notice.", "patients", true, false);
        var v2 = v1 with { Version = 2, Revision = 2,
            Text = "Specialist cancellations require 72 hours' notice." };
        Check(lab.TryChangeControl(scope, 0, ServingMode.Normal, v1Bundle), "initial control installed");
        Check(lab.TryChangeControl(other, 0, ServingMode.Normal, fixedBundle), "other tenant configured");
        lab.SetPolicy(v1);
        var oldCache = new Draft(v1, v1Bundle, v1.Text, true);
        lab.SetPolicy(v2);

        // snippet:reproduce
        // The old cache path returned text without checking current evidence.
        string LegacyCacheRead(Draft cached) => cached.Text;
        Check(LegacyCacheRead(oldCache).Contains("48"), "known defect reproduced");
        var request = lab.Begin("request-1", scope, "patients");
        Check(!lab.CanReuse(request, oldCache), "stale cache rejected");
        Check(lab.Commit(request, oldCache).Kind == "Blocked", "stale answer blocked at commit");
        // end:reproduce

        var fresh = new Draft(v2, v1Bundle, v2.Text, false);
        var inFlight = lab.Begin("request-in-flight", scope, "patients");
        // snippet:containment-checks
        Check(lab.Contain(scope, 1, v1Bundle), "containment applied");
        Check(lab.Commit(inFlight, fresh).Kind == "Blocked", "in-flight answer blocked");
        Check(!lab.TryChangeControl(scope, 1, ServingMode.Normal, fixedBundle),
            "stale operator update rejected");
        Check(lab.ReadControl(other).Mode == ServingMode.Normal, "other tenant unchanged");
        var contained = lab.Begin("request-contained", scope, "patients");
        Check(lab.ReadSources(contained).Text.Contains("72"), "current source remains available");
        // end:containment-checks
        Check(lab.Commit(contained, fresh).Kind == "Blocked", "generation remains disabled");
        Check(lab.ReadSources(lab.Begin("wrong-group", scope, "staff")).Kind == "Unavailable",
            "sources-only enforces access");
        Check(!lab.TryChangeControl(scope, 2, ServingMode.Normal, v1Bundle), "quarantined rollback rejected");

        var now = new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);
        // Fabricated report fixture tests the gate; it is NOT production evidence.
        var report = new RecoveryReport(fixedBundle, v2.Revision, now,
            "synthetic-lab", RecoveryGate.Required.Select(n => new CheckResult(n, true)).ToArray());
        Check(RecoveryGate.AcceptsLabReport(report, fixedBundle, 2, now), "complete fixture accepted by lab gate");
        Check(!RecoveryGate.AcceptsLabReport(report with { Checks = report.Checks[..^1] }, fixedBundle, 2, now),
            "missing recovery check rejected");
        Check(!RecoveryGate.AcceptsLabReport(report with { Checks = report.Checks.Select((c, i) =>
            i == 0 ? c with { Passed = false } : c).ToArray() }, fixedBundle, 2, now), "failed recovery check rejected");
        Check(!RecoveryGate.AcceptsLabReport(report with { Checks = report.Checks.Select((c, i) =>
            i == 0 ? report.Checks[1] : c).ToArray() }, fixedBundle, 2, now), "duplicate recovery check rejected");
        Check(!RecoveryGate.AcceptsLabReport(report, v1Bundle, 2, now), "different candidate rejected");
        Check(!RecoveryGate.AcceptsLabReport(report, fixedBundle, 3, now), "different evidence revision rejected");
        Check(!RecoveryGate.AcceptsLabReport(report, fixedBundle, 2, now.AddMinutes(31)), "expired report rejected");
        Check(!RecoveryGate.AcceptsLabReport(report, fixedBundle, 2, now.AddMinutes(-1)), "future report rejected");
        Check(!RecoveryGate.AcceptsLabReport(report with { Provenance = "production" }, fixedBundle, 2, now),
            "lab gate rejects a different provenance label");

        // snippet:resume
        bool resumed = RecoveryGate.AcceptsLabReport(report, fixedBundle, 2, now)
            && lab.TryChangeControl(scope, 2, ServingMode.Normal, fixedBundle);
        Check(resumed, "lab candidate resumed");
        // end:resume
        var recovered = lab.Begin("request-recovered", scope, "patients");
        var repaired = new Draft(v2, fixedBundle, v2.Text, false);
        Check(lab.Commit(recovered, repaired).Text.Contains("72"), "current answer committed");
        Check(!lab.CanReuse(recovered, fresh with { CacheHit = true }), "old release cache rejected");
        Check(lab.CanReuse(recovered, repaired with { CacheHit = true }), "current release cache eligible");
        Check(lab.Commit(lab.Begin("wrong-tenant", other, "patients"), repaired).Kind == "Blocked",
            "cross-tenant answer blocked");
        Check(lab.ReadReceipts().Single().SourceVersion == 2, "receipt records current source");
        Check(lab.ReadReceipts().Single().OriginBundle == fixedBundle, "receipt records answer origin");

        lab.SetPolicy(v2 with { Revision = 3, Group = "staff" });
        Check(lab.Commit(recovered, repaired).Kind == "Blocked", "access change blocks prepared answer");
        var restricted = v2 with { Revision = 3, Group = "staff" };
        var staff = lab.Begin("request-staff", scope, "staff");
        var staffDraft = repaired with { Evidence = restricted };
        Check(lab.CanReuse(staff, staffDraft), "new access snapshot is eligible");
        lab.SetPolicy(restricted with { Revision = 4, Deleted = true, Approved = false });
        Check(lab.Commit(staff, staffDraft).Kind == "Blocked", "deletion blocks prepared answer");
        Check(lab.ReadSources(staff).Kind == "Unavailable", "deleted source is unavailable");
        Check(lab.TryChangeControl(scope, 3, ServingMode.Paused, fixedBundle), "pause applied");
        Check(lab.ReadSources(lab.Begin("request-paused", scope, "staff")).Kind == "Blocked", "pause blocks source delivery");
        Check(lab.ReadSources(lab.Begin("unconfigured", new Scope("unknown", "policy-assistant"), "patients")).Kind == "Blocked",
            "unconfigured scope defaults to paused");

        // snippet:booking-checks
        var operation = new BookingOperation("clinic-a", "operation-7",
            BookingState.Succeeded, "booking-42");
        Check(BookingRecovery.Explain(operation) == "Booking confirmed: booking-42.",
            "lost confirmation reconstructed from booking record");
        Check(BookingRecovery.Explain(operation with { State = BookingState.Unknown })
            .Contains("Do not submit a duplicate"), "unknown outcome requires reconciliation");
        Check(BookingRecovery.Explain(operation with { BookingId = null })
            .Contains("reconciliation"), "inconsistent success record requires reconciliation");
        // end:booking-checks
        Console.WriteLine($"All {checks} incident recovery checks passed.");
    }
}
