using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// BCL-only .NET 10 console drill. No JWT validation, model, database, search
// service, distributed coordination, HTTP server, or actual background worker.
// All administrative methods represent already-authorized control-plane actions.

// snippet:identities
public sealed record Subject(string Issuer, string Id);
public sealed record TenantProfile(string Id, long Revision, bool Enabled,
    string Release, string SearchIndex, string ModelRoute,
    int MaxConcurrent, long TokenBudget);
public sealed record Membership(Subject Subject, string TenantId,
    string Group, long Revision, bool Active);
public sealed class TenantScope
{
    internal TenantScope(TenantProfile profile, Membership membership)
        => (Profile, Member) = (profile, membership);
    public TenantProfile Profile { get; }
    public Membership Member { get; }
}
// end:identities

public sealed record Document(string TenantId, string Id, long Revision,
    string Group, string Text, bool Approved = true, bool Deleted = false);
public sealed record Evidence(Document Source, string Index);
public sealed record Conversation(string TenantId, string Id, Subject Owner, string[] Messages);

// snippet:cache-identity
public sealed record CacheIdentity(string TenantId, Subject Subject,
    long MembershipRevision, long ConfigRevision, string Release,
    string Index, string Locale, string Question);
public sealed record CachedAnswer(CacheIdentity Identity, Evidence Evidence, string Text);
// end:cache-identity

public sealed record BackgroundJob(string Id, string TenantId, Subject Subject,
    long MembershipRevision, long ConfigRevision, string Payload);
public sealed record JobPlan(TenantScope Scope, string Payload);
public sealed record Booking(string TenantId, string Id, Subject Owner, string State);
public sealed record Usage(int Running = 0, long Charged = 0, long Held = 0);
public sealed record Reservation(string Id, string TenantId, long Ceiling);

public sealed class TenantPlatform
{
    private readonly object sync = new();
    private readonly Dictionary<string, TenantProfile> tenants = new();
    private readonly Dictionary<(Subject, string), Membership> memberships = new();
    private readonly Dictionary<(string, string), Document> documents = new();
    private readonly Dictionary<(string, string), Conversation> conversations = new();
    private readonly Dictionary<string, CachedAnswer> cache = new();
    private readonly Dictionary<string, BackgroundJob> jobs = new();
    private readonly Dictionary<(string, Subject, string), string> acceptedRequests = new();
    private readonly Dictionary<(string, string), Booking> bookings = new();
    private readonly Dictionary<string, Usage> usage = new();
    private readonly Dictionary<string, Reservation> reservations = new();
    private readonly byte[] cacheSecret = RandomNumberGenerator.GetBytes(32);

    public void Configure(string tenant, bool enabled, string release, string index,
        string modelRoute, int maxConcurrent = 1, long tokenBudget = 100)
    {
        lock (sync)
        {
            if (maxConcurrent < 1 || tokenBudget < 1) throw new ArgumentOutOfRangeException();
            if (modelRoute is not ("shared-model" or "dedicated-model"))
                throw new ArgumentException("Unknown model route.");
            long revision = tenants.TryGetValue(tenant, out var old) ? old.Revision + 1 : 1;
            tenants[tenant] = new(tenant, revision, enabled, release, index,
                modelRoute, maxConcurrent, tokenBudget);
        }
    }
    public void SetMembership(Subject subject, string tenant, string group, bool active = true)
    {
        lock (sync)
        {
            if (!tenants.ContainsKey(tenant)) throw new ArgumentException("Unknown tenant.");
            long revision = memberships.TryGetValue((subject, tenant), out var old) ? old.Revision + 1 : 1;
            memberships[(subject, tenant)] = new(subject, tenant, group, revision, active);
        }
    }
    public void PutDocument(Document document)
    {
        lock (sync)
        {
            if (documents.TryGetValue((document.TenantId, document.Id), out var old)
                && document.Revision <= old.Revision) throw new ArgumentException("Revision must increase.");
            documents[(document.TenantId, document.Id)] = document;
        }
    }
    public void SeedBooking(Booking booking)
    { lock (sync) bookings.Add((booking.TenantId, booking.Id), booking); }

    // Subject must come from validated authentication, never an HTTP body.
    // snippet:resolve
    public TenantScope Resolve(Subject authenticated, string selectedTenant)
    {
        lock (sync)
        {
            if (!tenants.TryGetValue(selectedTenant, out var profile) || !profile.Enabled
                || !memberships.TryGetValue((authenticated, selectedTenant), out var member)
                || !member.Active) throw new SecurityException("Tenant access denied.");
            return new TenantScope(profile, member);
        }
    }
    // end:resolve

    // snippet:revalidate
    private void RequireCurrent(TenantScope scope)
    {
        if (!tenants.TryGetValue(scope.Profile.Id, out var profile)
            || profile != scope.Profile || !profile.Enabled
            || !memberships.TryGetValue((scope.Member.Subject, profile.Id), out var member)
            || member != scope.Member || !member.Active)
            throw new SecurityException("Tenant scope is no longer current.");
    }
    // end:revalidate

    private static bool Allowed(TenantScope scope, Document document) =>
        document.TenantId == scope.Profile.Id && document.Group == scope.Member.Group
        && document.Approved && !document.Deleted;

    // snippet:retrieval
    public Evidence[] Retrieve(TenantScope scope, string term)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            return documents.Values.Where(d => Allowed(scope, d))
                .Where(d => d.Text.Contains(term, StringComparison.OrdinalIgnoreCase))
                .Select(d => new Evidence(d, scope.Profile.SearchIndex)).ToArray();
        }
    }
    // end:retrieval

    // snippet:evidence-guard
    private bool CurrentEvidence(TenantScope scope, Evidence evidence) =>
        evidence.Index == scope.Profile.SearchIndex
        && documents.TryGetValue((scope.Profile.Id, evidence.Source.Id), out var current)
        && current == evidence.Source && Allowed(scope, current);

    public bool CanUseEvidence(TenantScope scope, Evidence evidence)
    {
        lock (sync) { RequireCurrent(scope); return CurrentEvidence(scope, evidence); }
    }
    // end:evidence-guard

    // snippet:cache-key
    private static CacheIdentity Identity(TenantScope scope, string question, string locale) =>
        new(scope.Profile.Id, scope.Member.Subject, scope.Member.Revision,
            scope.Profile.Revision, scope.Profile.Release, scope.Profile.SearchIndex,
            locale, question.Trim());

    private string CacheKey(CacheIdentity identity) => Convert.ToHexString(
        HMACSHA256.HashData(cacheSecret, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(identity))));
    // end:cache-key

    public void CacheAnswer(TenantScope scope, string question, string locale,
        Evidence evidence, string validatedAnswer)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            if (!CurrentEvidence(scope, evidence)) throw new SecurityException("Ineligible evidence.");
            var identity = Identity(scope, question, locale);
            cache[CacheKey(identity)] = new(identity, evidence, validatedAnswer);
        }
    }

    // snippet:cache-read
    public string? ReadCached(TenantScope scope, string question, string locale)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            var expected = Identity(scope, question, locale);
            return cache.TryGetValue(CacheKey(expected), out var saved)
                && saved.Identity == expected && CurrentEvidence(scope, saved.Evidence)
                ? saved.Text : null;
        }
    }
    // end:cache-read

    public void AppendConversation(TenantScope scope, string id, string message)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            var key = (scope.Profile.Id, id);
            if (conversations.TryGetValue(key, out var saved) && saved.Owner != scope.Member.Subject)
                throw new SecurityException("Conversation access denied.");
            conversations[key] = new(scope.Profile.Id, id, scope.Member.Subject,
                [.. (saved?.Messages ?? Array.Empty<string>()), message]);
        }
    }

    // snippet:conversation
    public string[] ReadConversation(TenantScope scope, string id)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            if (!conversations.TryGetValue((scope.Profile.Id, id), out var saved)
                || saved.Owner != scope.Member.Subject)
                throw new SecurityException("Conversation access denied.");
            return saved.Messages.ToArray();
        }
    }
    // end:conversation

    // snippet:tool
    public string ReadBooking(TenantScope scope, string bookingId)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            if (!bookings.TryGetValue((scope.Profile.Id, bookingId), out var booking)
                || booking.Owner != scope.Member.Subject)
                throw new SecurityException("Booking access denied.");
            return booking.State;
        }
    }
    // end:tool

    // snippet:job-accept
    public BackgroundJob AcceptJob(TenantScope scope, string requestKey, string payload)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            var key = (scope.Profile.Id, scope.Member.Subject, requestKey);
            if (acceptedRequests.TryGetValue(key, out var id))
                return jobs[id].Payload == payload ? jobs[id]
                    : throw new InvalidOperationException("Request key payload conflict.");
            var job = new BackgroundJob(Guid.NewGuid().ToString("N"), scope.Profile.Id,
                scope.Member.Subject, scope.Member.Revision, scope.Profile.Revision, payload);
            jobs.Add(job.Id, job); acceptedRequests.Add(key, job.Id);
            return job;
        }
    }
    // end:job-accept

    // snippet:job-resume
    public JobPlan ResumeJob(string jobId)
    {
        lock (sync)
        {
            var job = jobs[jobId];
            var scope = Resolve(job.Subject, job.TenantId);
            if (scope.Member.Revision != job.MembershipRevision
                || scope.Profile.Revision != job.ConfigRevision)
                throw new SecurityException("Job requires an explicit reauthorization decision.");
            return new(scope, job.Payload);
        }
    }
    // end:job-resume

    // snippet:reserve
    public Reservation? TryReserve(TenantScope scope, long ceiling)
    {
        lock (sync)
        {
            RequireCurrent(scope);
            if (ceiling <= 0) throw new ArgumentOutOfRangeException(nameof(ceiling));
            var current = usage.GetValueOrDefault(scope.Profile.Id) ?? new Usage();
            long available = current.Charged >= scope.Profile.TokenBudget
                ? 0 : scope.Profile.TokenBudget - current.Charged;
            if (current.Running >= scope.Profile.MaxConcurrent
                || current.Held > available || ceiling > available - current.Held) return null;
            var ticket = new Reservation(Guid.NewGuid().ToString("N"), scope.Profile.Id, ceiling);
            reservations.Add(ticket.Id, ticket);
            usage[scope.Profile.Id] = current with { Running = current.Running + 1,
                Held = current.Held + ceiling };
            return ticket;
        }
    }
    // end:reserve

    // Trusted usage settlement can run even after tenant access is revoked.
    // snippet:settle
    public bool Settle(Reservation ticket, long? actualTokens)
    {
        lock (sync)
        {
            if (!reservations.TryGetValue(ticket.Id, out var saved) || saved != ticket) return false;
            long charge = actualTokens ?? saved.Ceiling;
            if (charge < 0) throw new ArgumentOutOfRangeException(nameof(actualTokens));
            var current = usage[saved.TenantId];
            usage[saved.TenantId] = new(current.Running - 1,
                checked(current.Charged + charge), current.Held - saved.Ceiling);
            reservations.Remove(ticket.Id);
            return true;
        }
    }
    // end:settle

    public Usage ReadUsage(string tenant)
    { lock (sync) return usage.GetValueOrDefault(tenant) ?? new Usage(); }
}

public static class Program
{
    private static int checks;
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException($"FAIL: {message}");
        checks++; Console.WriteLine($"PASS: {message}");
    }
    private static void Denied(Action action, string message)
    {
        bool denied = false;
        try { action(); } catch (SecurityException) { denied = true; }
        Check(denied, message);
    }
    private static void Conflict(Action action, string message)
    {
        bool conflict = false;
        try { action(); } catch (InvalidOperationException) { conflict = true; }
        Check(conflict, message);
    }

    public static void Main()
    {
        var app = new TenantPlatform();
        var alice = new Subject("trusted-issuer", "alice");
        var bob = new Subject("trusted-issuer", "bob");
        var carol = new Subject("trusted-issuer", "carol");
        app.Configure("clinic-a", true, "release-1", "shared-policy-index", "shared-model");
        app.Configure("clinic-b", true, "release-1", "shared-policy-index", "dedicated-model");
        app.SetMembership(alice, "clinic-a", "patients");
        app.SetMembership(bob, "clinic-b", "patients");
        app.SetMembership(carol, "clinic-a", "patients");
        var a = app.Resolve(alice, "clinic-a");
        var b = app.Resolve(bob, "clinic-b");
        var anotherA = app.Resolve(carol, "clinic-a");
        Denied(() => app.Resolve(alice, "clinic-b"), "tenant selector cannot grant membership");
        Denied(() => app.Resolve(new Subject("other-issuer", "alice"), "clinic-a"), "subject identity includes issuer");
        Denied(() => app.Resolve(alice, "unknown"), "unknown tenant is denied");

        var policyA = new Document("clinic-a", "cancellation", 1, "patients",
            "Specialist cancellations require 48 hours' notice.");
        var policyB = new Document("clinic-b", "cancellation", 1, "patients",
            "Specialist cancellations require 72 hours' notice.");
        app.PutDocument(policyA); app.PutDocument(policyB);
        app.PutDocument(new("clinic-a", "staff-only", 1, "staff", "Specialist internal escalation details."));
        var evidenceA = app.Retrieve(a, "specialist").Single();
        var evidenceB = app.Retrieve(b, "specialist").Single();

        // snippet:isolation-checks
        Check(evidenceA.Source.Text.Contains("48"), "clinic A receives its own policy");
        Check(evidenceB.Source.Text.Contains("72"), "clinic B receives its own policy");
        Check(!app.CanUseEvidence(a, evidenceB), "foreign evidence rejected despite matching document ID");
        app.CacheAnswer(a, "cancellation?", "en", evidenceA, "48 hours.");
        Check(app.ReadCached(a, "cancellation?", "en") == "48 hours.", "authorized cache hit works");
        Check(app.ReadCached(b, "cancellation?", "en") is null, "cache is isolated by tenant");
        Check(app.ReadCached(anotherA, "cancellation?", "en") is null, "cache is isolated by user");
        Check(app.ReadCached(a, "cancellation?", "fr") is null, "cache is isolated by locale");
        // end:isolation-checks

        var dualUser = new Subject("trusted-issuer", "dual-user");
        app.SetMembership(dualUser, "clinic-a", "patients");
        app.SetMembership(dualUser, "clinic-b", "patients");
        var dualA = app.Resolve(dualUser, "clinic-a");
        var dualB = app.Resolve(dualUser, "clinic-b");
        app.CacheAnswer(dualA, "cancellation?", "en", evidenceA, "48 hours.");
        Check(app.ReadCached(dualB, "cancellation?", "en") is null,
            "same user and release cannot reuse another tenant's cache");

        Denied(() => app.CacheAnswer(a, "cancellation?", "en", evidenceB, "72 hours."), "foreign evidence cannot populate cache");
        app.AppendConversation(a, "conversation-1", "Clinic A private message.");
        app.AppendConversation(b, "conversation-1", "Clinic B private message.");
        Check(app.ReadConversation(a, "conversation-1").Single().Contains("Clinic A"), "conversation ID scoped to tenant");
        Check(app.ReadConversation(b, "conversation-1").Single().Contains("Clinic B"), "overlapping conversation IDs stay separate");
        Denied(() => app.ReadConversation(anotherA, "conversation-1"), "tenant membership alone cannot read another user's conversation");
        Denied(() => app.AppendConversation(anotherA, "conversation-1", "injected"), "tenant membership alone cannot modify another user's conversation");
        app.SeedBooking(new("clinic-a", "booking-17", alice, "Clinic A booking confirmed."));
        app.SeedBooking(new("clinic-b", "booking-17", bob, "Clinic B booking pending."));
        Check(app.ReadBooking(a, "booking-17").Contains("Clinic A"), "tool lookup uses trusted tenant context");
        Denied(() => app.ReadBooking(anotherA, "booking-17"), "tool enforces resource ownership");

        var job = app.AcceptJob(a, "request-1", "summarise-consultation-17");
        Check(app.AcceptJob(a, "request-1", job.Payload).Id == job.Id, "acceptance retry returns original job");
        Conflict(() => app.AcceptJob(a, "request-1", "different-payload"), "acceptance key rejects changed payload");
        var otherJob = app.AcceptJob(b, "request-1", job.Payload);
        Check(otherJob.Id != job.Id, "same request key is separate across tenants");
        Check(app.ResumeJob(job.Id).Scope.Profile.Id == "clinic-a", "worker reconstructs tenant from job ledger");

        var ticketA = app.TryReserve(a, 80)!;
        Check(ticketA is not null, "clinic A obtains a reservation");
        Check(app.TryReserve(anotherA, 10) is null, "tenant concurrency limit applies across users");
        var ticketB = app.TryReserve(b, 20)!;
        Check(ticketB is not null, "clinic B retains its own admission capacity");
        Check(app.Settle(ticketA, 30), "actual usage settles reservation");
        Check(!app.Settle(ticketA, 30), "duplicate settlement cannot double charge");
        Check(app.ReadUsage("clinic-a") == new Usage(0, 30, 0), "unused reservation released");
        var unknown = app.TryReserve(a, 70)!;
        Check(app.Settle(unknown, null), "unknown usage charged conservatively");
        Check(app.TryReserve(a, 1) is null, "exhausted tenant budget blocks admission");
        Check(app.ReadUsage("clinic-b") == new Usage(1, 0, 20), "one tenant's budget does not alter another's ledger");

        app.PutDocument(policyA with { Revision = 2, Text = "Specialist cancellations require 96 hours' notice." });
        Check(app.ReadCached(a, "cancellation?", "en") is null, "policy update invalidates cached evidence");
        Check(!app.CanUseEvidence(a, evidenceA), "old evidence blocked at use boundary");
        var newEvidence = app.Retrieve(a, "specialist").Single();
        app.CacheAnswer(a, "cancellation?", "en", newEvidence, "96 hours.");
        app.PutDocument(newEvidence.Source with { Revision = 3, Approved = false, Deleted = true });
        Check(app.ReadCached(a, "cancellation?", "en") is null, "source deletion invalidates cache");
        Check(app.Retrieve(a, "specialist").Length == 0, "deleted and unauthorized documents are excluded");

        app.SetMembership(alice, "clinic-a", "patients", active: false);
        Denied(() => app.ReadCached(a, "cancellation?", "en"), "revoked membership invalidates old scope");
        Denied(() => app.ResumeJob(job.Id), "revoked membership blocks queued job");
        Check(app.ReadBooking(b, "booking-17").Contains("Clinic B"), "other tenant remains authorized");
        app.SetMembership(alice, "clinic-a", "patients");
        a = app.Resolve(alice, "clinic-a");
        Denied(() => app.ResumeJob(job.Id), "restored membership does not silently reauthorize old job");

        app.Configure("clinic-a", true, "release-a2", "new-index", "shared-model");
        Denied(() => app.Retrieve(a, "specialist"), "configuration change invalidates captured scope");
        a = app.Resolve(alice, "clinic-a");
        Check(a.Profile.Release == "release-a2", "new scope captures approved release");
        Check(app.TryReserve(a, 1) is null, "configuration update does not reset usage budget");
        var pinnedJob = app.AcceptJob(a, "request-2", "summarise-consultation-17");
        app.Configure("clinic-a", true, "release-a3", "new-index", "shared-model");
        Denied(() => app.ResumeJob(pinnedJob.Id), "job cannot silently change its pinned configuration");

        app.Configure("clinic-b", false, "release-b", "shared-policy-index", "dedicated-model");
        Denied(() => app.Resolve(bob, "clinic-b"), "disabled tenant cannot obtain new scope");
        Denied(() => app.ReadConversation(b, "conversation-1"), "disabled tenant cannot reuse existing scope");
        Denied(() => app.ResumeJob(otherJob.Id), "disabled tenant cannot resume accepted jobs");
        Check(app.Settle(ticketB, 12), "in-flight usage settles against original tenant after disable");
        Console.WriteLine($"All {checks} multi-tenant checks passed.");
    }
}
