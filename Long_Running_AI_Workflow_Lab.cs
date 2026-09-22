using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// BCL-only .NET 10 console drill. One workflow per directory, one store owner.
// Synthetic model and review service. File persistence is for local learning,
// not a distributed database or a guarantee against power loss/filesystem failure.

// snippet:state
public enum Step { GenerateDraft, SubmitForReview, Done }
public enum RunState { Ready, Running, Completed, Cancelled, Expired, Failed, NeedsAttention }
public sealed record Workflow(
    string Id, string Tenant, string ConsultationId, long TranscriptVersion,
    string DefinitionVersion, string ReleaseId, DateTimeOffset Deadline,
    Step Next = Step.GenerateDraft, RunState State = RunState.Ready,
    bool CancelRequested = false, long Epoch = 0, string? Owner = null,
    DateTimeOffset LeaseUntil = default, int Attempts = 0, long GenerationEpoch = 0,
    DateTimeOffset NextAttemptAt = default, string? Draft = null,
    string? DraftHash = null, string? ReviewKey = null, string? ReviewTaskId = null);
public sealed record Lease(string WorkflowId, string Owner, long Epoch);
// end:state

public static class Files
{
    public static readonly JsonSerializerOptions Json = new() {
        WriteIndented = true, Converters = { new JsonStringEnumConverter() }
    };
    public static string Digest(params string[] values) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(values))));

    // snippet:persist
    public static void Save<T>(string path, T value)
    {
        string temporary = path + ".pending";
        using (var stream = new FileStream(temporary, FileMode.Create,
            FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, value, Json);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
    }
    // end:persist
}

public sealed class WorkflowStore : IDisposable
{
    private readonly object sync = new();
    private readonly string path;
    private readonly FileStream ownership;
    private readonly Func<DateTimeOffset> clock;
    private Workflow value;
    private bool unusable;

    public WorkflowStore(string directory, Func<DateTimeOffset> clock, Workflow? seed = null)
    {
        Directory.CreateDirectory(directory);
        ownership = new FileStream(Path.Combine(directory, "owner.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        this.clock = clock;
        path = Path.Combine(directory, "workflow.json");
        try
        {
            if (File.Exists(path))
                value = JsonSerializer.Deserialize<Workflow>(File.ReadAllText(path), Files.Json)
                    ?? throw new InvalidDataException("Missing workflow state.");
            else
            {
                value = seed ?? throw new FileNotFoundException("No saved workflow.");
                Files.Save(path, value);
            }
        }
        catch { ownership.Dispose(); throw; }
    }

    private void Save(Workflow next)
    {
        EnsureUsable();
        try { Files.Save(path, next); value = next; }
        catch { unusable = true; throw; } // Reopen after any uncertain write.
    }
    private void EnsureUsable() => ObjectDisposedException.ThrowIf(unusable, this);
    public Workflow Read() { lock (sync) { EnsureUsable(); return value; } }
    public void Dispose() { lock (sync) { unusable = true; ownership.Dispose(); } }
    private static bool Terminal(RunState state) => state is RunState.Completed
        or RunState.Cancelled or RunState.Expired or RunState.Failed or RunState.NeedsAttention;

    // snippet:acquire
    public Lease? TryAcquire(string owner, string definition, string release)
    {
        lock (sync)
        {
            EnsureUsable();
            if (value.DefinitionVersion != definition || value.ReleaseId != release)
                throw new InvalidOperationException("Worker cannot execute this pinned version.");
            if (Terminal(value.State)) return null;
            if (value.ReviewKey is null && clock() >= value.Deadline)
            { Save(value with { State = RunState.Expired, Owner = null }); return null; }
            if (clock() < value.NextAttemptAt || value.LeaseUntil > clock()) return null;
            Save(value with { Owner = owner, Epoch = value.Epoch + 1,
                LeaseUntil = clock().AddSeconds(30), State = RunState.Running });
            return new(value.Id, owner, value.Epoch);
        }
    }
    // end:acquire

    // snippet:fence
    private bool Owns(Lease lease) => !unusable && value.State == RunState.Running
        && value.Id == lease.WorkflowId && value.Owner == lease.Owner
        && value.Epoch == lease.Epoch && value.LeaseUntil > clock();

    public bool Renew(Lease lease)
    {
        lock (sync)
        {
            if (!Owns(lease)) return false;
            Save(value with { LeaseUntil = clock().AddSeconds(30) });
            return true;
        }
    }
    // end:fence

    // snippet:reserve
    public bool ReserveGeneration(Lease lease)
    {
        lock (sync)
        {
            if (!Owns(lease) || value.Next != Step.GenerateDraft
                || value.CancelRequested || clock() >= value.Deadline
                || value.GenerationEpoch == lease.Epoch) return false;
            if (value.Attempts >= 3)
            { Save(value with { State = RunState.Failed, Owner = null }); return false; }
            Save(value with { Attempts = value.Attempts + 1, GenerationEpoch = lease.Epoch });
            return true;
        }
    }
    // end:reserve

    // snippet:checkpoint
    public bool CheckpointDraft(Lease lease, string validatedDraft)
    {
        lock (sync)
        {
            if (!Owns(lease) || value.Next != Step.GenerateDraft || value.GenerationEpoch != lease.Epoch
                || value.CancelRequested || clock() >= value.Deadline) return false;
            if (string.IsNullOrWhiteSpace(validatedDraft)) throw new ArgumentException("Empty draft.");
            var hash = Files.Digest(value.Tenant, value.Id, value.ReleaseId, validatedDraft);
            Save(value with { Draft = validatedDraft, DraftHash = hash,
                Next = Step.SubmitForReview, State = RunState.Ready,
                Owner = null, LeaseUntil = default, NextAttemptAt = default });
            return true;
        }
    }
    // end:checkpoint

    // snippet:retry
    public bool ScheduleGenerationRetry(Lease lease)
    {
        lock (sync)
        {
            if (!Owns(lease) || value.Next != Step.GenerateDraft || value.GenerationEpoch != lease.Epoch)
                return false;
            var due = clock().AddSeconds(Math.Pow(2, value.Attempts));
            var state = value.Attempts >= 3 ? RunState.Failed
                : due >= value.Deadline ? RunState.Expired : RunState.Ready;
            Save(value with { State = state, NextAttemptAt = due,
                Owner = null, LeaseUntil = default });
            return true;
        }
    }
    // end:retry

    // snippet:cancel
    public string RequestCancellation()
    {
        lock (sync)
        {
            EnsureUsable();
            if (Terminal(value.State)) return $"Already {value.State}";
            if (value.ReviewKey is not null)
            {
                Save(value with { CancelRequested = true });
                return "Cancellation requested; reconcile submission.";
            }
            Save(value with { CancelRequested = true, State = RunState.Cancelled,
                Epoch = value.Epoch + 1, Owner = null, LeaseUntil = default });
            return "Cancelled before submission intent.";
        }
    }
    // end:cancel

    // snippet:intent
    public string? BeginSubmission(Lease lease)
    {
        lock (sync)
        {
            if (!Owns(lease) || value.Next != Step.SubmitForReview
                || value.CancelRequested || clock() >= value.Deadline
                || value.DraftHash is null) return null;
            if (value.ReviewKey is not null) return value.ReviewKey;
            var key = Files.Digest(value.Tenant, value.Id, "create-review-task");
            Save(value with { ReviewKey = key });
            return key;
        }
    }
    // end:intent

    // These predicates grant a local dispatch decision, not an atomic network send.
    public bool MayDispatch(Lease lease)
    {
        lock (sync) return Owns(lease) && value.Next == Step.SubmitForReview
            && value.ReviewKey is not null && !value.CancelRequested && clock() < value.Deadline;
    }

    // snippet:complete
    public bool RecordSubmission(Lease lease, ReviewTask? receipt)
    {
        lock (sync)
        {
            if (!Owns(lease) || value.ReviewKey is null || value.Next != Step.SubmitForReview)
                return false;
            if (receipt is null)
            { Save(value with { State = RunState.NeedsAttention, Owner = null }); return true; }
            if (receipt.Key != value.ReviewKey || receipt.PayloadHash != value.DraftHash)
                throw new InvalidOperationException("Submission receipt mismatch.");
            Save(value with { ReviewTaskId = receipt.Id, Next = Step.Done,
                State = RunState.Completed, Owner = null, LeaseUntil = default });
            return true;
        }
    }
    // end:complete
}

public sealed record ReviewTask(string Key, string PayloadHash, string Id);
public sealed class ReviewInbox : IDisposable
{
    private readonly string path;
    private readonly FileStream ownership;
    private readonly object sync = new();
    private Dictionary<string, ReviewTask> tasks;
    private bool unusable;
    public ReviewInbox(string directory)
    {
        Directory.CreateDirectory(directory);
        ownership = new FileStream(Path.Combine(directory, "inbox-owner.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        path = Path.Combine(directory, "inbox.json");
        try
        {
            tasks = File.Exists(path)
                ? JsonSerializer.Deserialize<Dictionary<string, ReviewTask>>(File.ReadAllText(path), Files.Json)
                    ?? throw new InvalidDataException("Missing inbox state.")
                : new();
        }
        catch { ownership.Dispose(); throw; }
    }
    public int Count { get { lock (sync) { EnsureUsable(); return tasks.Count; } } }
    public ReviewTask? Find(string key)
    { lock (sync) { EnsureUsable(); return tasks.GetValueOrDefault(key); } }
    private void EnsureUsable() => ObjectDisposedException.ThrowIf(unusable, this);
    public void Dispose() { lock (sync) { unusable = true; ownership.Dispose(); } }

    // snippet:idempotent-sink
    public ReviewTask CreateOnce(string key, string payloadHash)
    {
        lock (sync)
        {
            EnsureUsable();
            if (tasks.TryGetValue(key, out var existing))
                return existing.PayloadHash == payloadHash ? existing
                    : throw new InvalidOperationException("Idempotency key reused with different payload.");
            var task = new ReviewTask(key, payloadHash, Guid.NewGuid().ToString("N"));
            var next = new Dictionary<string, ReviewTask>(tasks) { [key] = task };
            try { Files.Save(path, next); tasks = next; }
            catch { unusable = true; throw; }
            return task;
        }
    }
    // end:idempotent-sink
}

public static class Worker
{
    // snippet:reconcile
    public static bool RecoverSubmission(WorkflowStore store, ReviewInbox inbox, Lease lease)
    {
        var saved = store.Read();
        if (saved.ReviewKey is null || saved.DraftHash is null) return false;
        var receipt = inbox.Find(saved.ReviewKey);
        if (receipt is not null) return store.RecordSubmission(lease, receipt);
        if (!store.MayDispatch(lease))
            return store.RecordSubmission(lease, null);
        receipt = inbox.CreateOnce(saved.ReviewKey, saved.DraftHash);
        return store.RecordSubmission(lease, receipt);
    }
    // end:reconcile

    // snippet:local-cancellation
    public static async Task<string> GenerateWithinBudgetAsync(
        Func<CancellationToken, Task<string>> generate, TimeSpan budget,
        CancellationToken workerStopping, CancellationToken businessCancellation)
    {
        if (budget <= TimeSpan.Zero) throw new TimeoutException("No generation budget remains.");
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(
            workerStopping, businessCancellation);
        attempt.CancelAfter(budget);
        return await generate(attempt.Token);
    }
    // end:local-cancellation
}

public sealed class ManualClock
{
    public DateTimeOffset Now { get; private set; } = new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);
    public void Advance(int seconds) => Now = Now.AddSeconds(seconds);
}

public static class Program
{
    private static int checks;
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException($"FAIL: {message}");
        checks++; Console.WriteLine($"PASS: {message}");
    }
    private static void Rejects(Action action, string message)
    {
        bool rejected = false;
        try { action(); } catch (InvalidOperationException) { rejected = true; }
        Check(rejected, message);
    }
    private static Workflow NewWorkflow(ManualClock clock, string id) => new(
        id, "clinic-a", "consultation-17", 4, "summary-workflow-v1", "ai-release-7",
        clock.Now.AddMinutes(10));
    private static Lease Claim(WorkflowStore store, string worker = "worker-a") =>
        store.TryAcquire(worker, "summary-workflow-v1", "ai-release-7")
        ?? throw new InvalidOperationException("Expected an available lease.");
    private static void MakeDraft(WorkflowStore store)
    {
        var lease = Claim(store);
        Check(store.ReserveGeneration(lease), "generation attempt reserved");
        Check(store.CheckpointDraft(lease, "Synthetic consultation draft; clinician review required."),
            "draft and next step checkpointed together");
    }

    public static async Task Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "status")
        {
            using var status = new WorkflowStore(Path.GetFullPath(args[1]), () => DateTimeOffset.UtcNow);
            Console.WriteLine(JsonSerializer.Serialize(status.Read(), Files.Json)); return;
        }
        if (args.Length != 0) throw new ArgumentException("Usage: no arguments, or status <workflow-directory>.");
        var root = Path.Combine(Environment.CurrentDirectory, "workflow-drill-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var clock = new ManualClock();
        var checkpointDirectory = Path.Combine(root, "checkpoint");
        using (var first = new WorkflowStore(checkpointDirectory, () => clock.Now, NewWorkflow(clock, "workflow-1")))
            MakeDraft(first);

        // snippet:restart-checks
        using (var reopened = new WorkflowStore(checkpointDirectory, () => clock.Now))
        {
            Check(reopened.Read().Next == Step.SubmitForReview, "restart resumes after generation");
            Check(reopened.Read().Attempts == 1, "restart preserves generation attempt count");
            var oldLease = Claim(reopened);
            Check(reopened.TryAcquire("worker-b", "summary-workflow-v1", "ai-release-7") is null,
                "live lease prevents a second claim");
            clock.Advance(31);
            var replacement = Claim(reopened, "worker-b");
            Check(replacement.Epoch > oldLease.Epoch, "takeover advances fencing epoch");
            Check(reopened.BeginSubmission(oldLease) is null, "stale worker cannot begin submission");
            Check(!reopened.Renew(oldLease), "stale worker cannot renew");
            Check(reopened.Renew(replacement), "current worker can renew");
        }
        // end:restart-checks

        var effectDirectory = Path.Combine(root, "effect");
        var inboxDirectory = Path.Combine(root, "review-service");
        string key, hash, taskId;
        using (var store = new WorkflowStore(effectDirectory, () => clock.Now, NewWorkflow(clock, "workflow-2")))
        using (var inbox = new ReviewInbox(inboxDirectory))
        {
            MakeDraft(store);
            var lease = Claim(store);
            key = store.BeginSubmission(lease)!; hash = store.Read().DraftHash!;
            var receipt = inbox.CreateOnce(key, hash); taskId = receipt.Id;
            Check(store.Read().ReviewTaskId is null, "crash window leaves local outcome unknown");
            Check(inbox.CreateOnce(key, hash).Id == taskId, "same key returns the original review task");
            Rejects(() => inbox.CreateOnce(key, "different-payload"), "changed payload is rejected");
            // Simulated crash: do not checkpoint receipt; dispose and reopen both stores.
        }
        clock.Advance(31);
        // snippet:effect-recovery-checks
        using (var store = new WorkflowStore(effectDirectory, () => clock.Now))
        using (var inbox = new ReviewInbox(inboxDirectory))
        {
            var lease = Claim(store, "replacement-worker");
            Check(Worker.RecoverSubmission(store, inbox, lease), "submission reconciled after restart");
            Check(store.Read().ReviewTaskId == taskId, "original external task retained");
            Check(inbox.Count == 1, "recovery creates no duplicate review task");
            Check(store.Read().State == RunState.Completed, "workflow completed from receipt");
            Check(store.RequestCancellation() == "Already Completed", "late cancellation does not undo completion");
        }
        // end:effect-recovery-checks

        using (var store = new WorkflowStore(Path.Combine(root, "cancel-before"), () => clock.Now, NewWorkflow(clock, "workflow-3")))
        {
            var lease = Claim(store);
            Check(store.ReserveGeneration(lease), "cancel scenario reserves generation");
            Check(store.RequestCancellation().StartsWith("Cancelled"), "cancellation before intent is terminal");
            Check(!store.CheckpointDraft(lease, "late draft"), "cancelled workflow discards late model output");
            Check(store.TryAcquire("another", "summary-workflow-v1", "ai-release-7") is null,
                "cancelled workflow cannot be claimed");
        }
        using (var reopened = new WorkflowStore(Path.Combine(root, "cancel-before"), () => clock.Now))
            Check(reopened.Read().CancelRequested, "cancellation survives reopening");

        using (var store = new WorkflowStore(Path.Combine(root, "cancel-after"), () => clock.Now, NewWorkflow(clock, "workflow-4")))
        using (var inbox = new ReviewInbox(Path.Combine(root, "cancel-after-service")))
        {
            MakeDraft(store);
            var lease = Claim(store);
            string operationKey = store.BeginSubmission(lease)!;
            var receipt = inbox.CreateOnce(operationKey, store.Read().DraftHash!);
            Check(store.RequestCancellation().Contains("reconcile"), "cancellation after intent requires reconciliation");
            Check(!store.MayDispatch(lease), "cancellation blocks a new dispatch decision");
            Check(Worker.RecoverSubmission(store, inbox, lease), "completed action reconciled despite cancellation");
            Check(store.Read().State == RunState.Completed && store.Read().CancelRequested,
                "completed outcome preserves cancellation request");
        }
        using (var store = new WorkflowStore(Path.Combine(root, "cancel-unknown"), () => clock.Now, NewWorkflow(clock, "workflow-5")))
        using (var inbox = new ReviewInbox(Path.Combine(root, "cancel-unknown-service")))
        {
            MakeDraft(store); var lease = Claim(store);
            store.BeginSubmission(lease); store.RequestCancellation();
            Check(Worker.RecoverSubmission(store, inbox, lease), "unknown cancelled submission recorded");
            Check(store.Read().State == RunState.NeedsAttention && inbox.Count == 0,
                "unknown outcome is not silently retried or declared cancelled");
        }

        var retryDirectory = Path.Combine(root, "retry");
        using (var store = new WorkflowStore(retryDirectory, () => clock.Now, NewWorkflow(clock, "workflow-6")))
        {
            var lease = Claim(store); store.ReserveGeneration(lease);
            Check(store.ScheduleGenerationRetry(lease), "retry schedule persisted");
            Check(store.TryAcquire("early", "summary-workflow-v1", "ai-release-7") is null, "retry delay is respected");
        }
        using (var store = new WorkflowStore(retryDirectory, () => clock.Now))
        {
            Check(store.Read().Attempts == 1 && store.Read().NextAttemptAt > clock.Now,
                "retry budget and due time survive reopening");
            clock.Advance(3); var second = Claim(store); store.ReserveGeneration(second);
            store.ScheduleGenerationRetry(second);
            clock.Advance(5); var third = Claim(store); store.ReserveGeneration(third);
            store.ScheduleGenerationRetry(third);
            Check(store.Read().Attempts == 3 && store.Read().State == RunState.Failed,
                "third failed attempt exhausts the durable budget");
        }
        using (var store = new WorkflowStore(Path.Combine(root, "deadline"), () => clock.Now, NewWorkflow(clock, "workflow-7")))
        {
            Rejects(() => store.TryAcquire("new-worker", "summary-workflow-v2", "ai-release-7"),
                "incompatible workflow definition rejected");
            Rejects(() => store.TryAcquire("new-worker", "summary-workflow-v1", "ai-release-8"),
                "different AI release rejected");
            var lease = Claim(store); store.ReserveGeneration(lease); clock.Advance(601);
            Check(!store.CheckpointDraft(lease, "late draft"), "late checkpoint rejected");
            Check(store.TryAcquire("late", "summary-workflow-v1", "ai-release-7") is null
                && store.Read().State == RunState.Expired, "business deadline persists across attempts");
        }
        using (var store = new WorkflowStore(Path.Combine(root, "deadline-live-lease"), () => clock.Now,
            NewWorkflow(clock, "workflow-8") with { Deadline = clock.Now.AddSeconds(10) }))
        {
            var lease = Claim(store); store.ReserveGeneration(lease);
            Check(!store.ReserveGeneration(lease), "one generation reservation per lease");
            clock.Advance(11);
            Check(!store.CheckpointDraft(lease, "late draft"), "deadline blocks commit even with a live lease");
        }
        using (var store = new WorkflowStore(Path.Combine(root, "lost-reservation"), () => clock.Now,
            NewWorkflow(clock, "workflow-9")))
        {
            var first = Claim(store); store.ReserveGeneration(first); clock.Advance(31);
            var second = Claim(store, "replacement");
            Check(!store.CheckpointDraft(second, "unreserved result"), "replacement needs its own generation reservation");
        }
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel(); bool observed = false;
            try
            {
                await Worker.GenerateWithinBudgetAsync(token => {
                    token.ThrowIfCancellationRequested(); return Task.FromResult("synthetic");
                }, TimeSpan.FromSeconds(10), CancellationToken.None, cancelled.Token);
            }
            catch (OperationCanceledException) { observed = true; }
            Check(observed, "cooperative cancellation reaches the model adapter");
        }
        Console.WriteLine($"All {checks} workflow checks passed.");
        Console.WriteLine($"Drill files retained at: {root}");
        Console.WriteLine("Use: dotnet run --project LongRunningWorkflowLab -- status <scenario-directory>");
    }
}
