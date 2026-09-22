// Copy this entire file to Program.cs in a .NET 10 console project.
// No NuGet packages, model calls, search service, or persistence are used.
// These C# checks were not executed in the authoring environment: no SDK.
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

var lab = new KnowledgeLab();
int checks = 0;
void Expect(bool condition, string name)
{
    if (!condition) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
    checks++;
}

const string tenant = "clinic-a";
const string document = "cancellation-policy";
const string group = "patients";
const string v1 = "Synthetic policy: General consultations require 24 hours notice.\nSpecialist consultations require 48 hours notice.";
const string v2 = "Synthetic policy v2: Specialist consultations require 72 hours notice.";

lab.ApproveVersion(tenant, document, 1, v1, group);
var blue = lab.Build(tenant, document, "knowledge-blue", "pipeline-v1");
lab.Upload(blue, skipOrdinal: 1);
Expect(!lab.TryPublish(blue), "partial upload cannot publish");
Expect(!lab.TryActivate(tenant, blue.IndexName, blue.Pipeline), "incomplete index cannot activate");
lab.Upload(blue);
Expect(lab.TryPublish(blue), "complete projection publishes");
Expect(lab.TryActivate(tenant, blue.IndexName, blue.Pipeline), "complete index activates");
Expect(lab.Read(tenant, group).Count == 2, "two v1 chunks are eligible");
lab.Upload(blue);
Expect(lab.StoredCount(tenant, document) == 2, "duplicate upload uses stable keys");
Expect(lab.Read(tenant, "unrelated-group").Count == 0, "wrong group receives no evidence");
Expect(lab.Read("clinic-b", group).Count == 0, "other tenant receives no evidence");

var green = lab.Build(tenant, document, "knowledge-green", "pipeline-v2");
lab.Upload(green, skipOrdinal: 1);
Expect(!lab.TryPublish(green), "partial rebuild cannot publish");
Expect(lab.Read(tenant, group).Count == 2, "blue continues during partial rebuild");
lab.Upload(green);
Expect(lab.TryPublish(green), "green projection publishes");
Expect(lab.TryActivate(tenant, green.IndexName, green.Pipeline), "green route activates");
var oldEvidence = lab.Read(tenant, group)[0];

lab.ApproveVersion(tenant, document, 2, v2, group);
Expect(lab.Read(tenant, group).Count == 0, "strict freshness blocks v1 after v2 approval");
Expect(!lab.CanReuse(tenant, group, oldEvidence), "old cache evidence is invalid");
Expect(!lab.TryPublish(blue), "old worker cannot republish v1");
var latest = lab.Build(tenant, document, green.IndexName, green.Pipeline);
lab.Upload(latest);
Expect(lab.TryPublish(latest), "v2 projection publishes");
Expect(lab.Read(tenant, group).Count == 1, "old trailing chunk is not eligible");
Expect(lab.Read(tenant, group)[0].Text.Contains("72"), "current evidence contains revised condition");
Expect(!lab.TryActivate(tenant, blue.IndexName, blue.Pipeline), "stale rollback target is blocked");

var beforeAccessChange = lab.Read(tenant, group)[0];
lab.ChangeGroup(tenant, document, "staff");
Expect(lab.Read(tenant, group).Count == 0, "access change immediately blocks old group");
Expect(!lab.CanReuse(tenant, group, beforeAccessChange), "access change invalidates cached evidence");
Expect(!lab.TryPublish(latest), "old metadata revision cannot publish");
var restricted = lab.Build(tenant, document, green.IndexName, green.Pipeline);
lab.Upload(restricted);
Expect(lab.TryPublish(restricted), "updated access projection publishes");
Expect(lab.Read(tenant, "staff").Count == 1, "current staff scope can read");

var deletionEvidence = lab.Read(tenant, "staff")[0];
lab.Delete(tenant, document);
Expect(lab.StoredCount(tenant, document) > 0, "tombstone precedes physical cleanup");
Expect(lab.Read(tenant, "staff").Count == 0, "tombstone blocks retained chunks");
Expect(!lab.TryPublish(restricted), "deleted document cannot republish");
lab.Purge(tenant, document);
Expect(lab.StoredCount(tenant, document) == 0, "all simulated index generations are purged");
Expect(lab.Upload(restricted) == 0, "late worker is refused after deletion");
Expect(!lab.CanReuse(tenant, "staff", deletionEvidence), "deleted evidence cannot be reused");
Console.WriteLine($"PASS: {checks} lifecycle checks.");

public sealed record SourceState(
    string TenantId, string DocumentId, long Version, long Revision,
    bool Approved, bool Deleted, string AllowedGroup);

public sealed record Chunk(
    string Key, string ProjectionId, string Text, int Ordinal);

public sealed record BuildPlan(
    SourceState Source, string IndexName, string Pipeline,
    string ProjectionId, IReadOnlyList<Chunk> Chunks);

public sealed record Evidence(
    string TenantId, string DocumentId, long SourceVersion,
    long SourceRevision, string IndexName, string Pipeline,
    string ProjectionId, string ChunkKey, string Text);

public sealed class KnowledgeLab
{
    // Single-process simulation. These dictionaries stand in for durable stores.
    private readonly object sync = new();
    private readonly Dictionary<(string, string), SourceState> sources = new();
    private readonly Dictionary<(string, string, long), string> bodies = new();
    private readonly Dictionary<(string, string), (BuildPlan Plan, Chunk Chunk)> index = new();
    private readonly Dictionary<(string, string, string), BuildPlan> published = new();
    private readonly Dictionary<string, (string Index, string Pipeline)> routes = new();

    private SourceState Current(string tenant, string document) => sources[(tenant, document)];

    public void ApproveVersion(string tenant, string document, long version, string text, string group)
    {
        lock (sync)
        {
            sources.TryGetValue((tenant, document), out var old);
            if (version < 1 || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(group)
                || old?.Deleted == true || version <= (old?.Version ?? 0))
                throw new InvalidOperationException("Invalid version, content, access group, or deleted identity.");
            bodies.Add((tenant, document, version), text);
            sources[(tenant, document)] = new SourceState(tenant, document, version,
                (old?.Revision ?? 0) + 1, true, false, group);
        }
    }

    public static string Digest(params string[] values) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(values)));

    public BuildPlan Build(string tenant, string document, string indexName, string pipeline)
    {
        lock (sync)
        {
            var source = Current(tenant, document);
            if (!source.Approved || source.Deleted)
                throw new InvalidOperationException("Source is not eligible.");
            string text = bodies[(tenant, document, source.Version)];
            string projection = Digest(tenant, document, indexName, pipeline,
                source.Version.ToString(CultureInfo.InvariantCulture),
                source.Revision.ToString(CultureInfo.InvariantCulture), Digest(text));
            var chunks = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select((part, ordinal) => new Chunk(
                    Digest(projection, ordinal.ToString(CultureInfo.InvariantCulture), part),
                    projection, part, ordinal)).ToArray();
            return new BuildPlan(source, indexName, pipeline, projection, Array.AsReadOnly(chunks));
        }
    }

    private bool IsCurrent(BuildPlan plan) =>
        sources.TryGetValue((plan.Source.TenantId, plan.Source.DocumentId), out var now)
        && now == plan.Source && now.Approved && !now.Deleted;

    public int Upload(BuildPlan plan, int? skipOrdinal = null)
    {
        lock (sync)
        {
            if (!IsCurrent(plan)) return 0;
            int written = 0;
            foreach (var chunk in plan.Chunks.Where(c => c.Ordinal != skipOrdinal))
            {
                index[(plan.IndexName, chunk.Key)] = (plan, chunk);
                written++;
            }
            return written;
        }
    }

    private bool Complete(BuildPlan plan) => plan.Chunks.Count > 0
        && plan.Chunks.All(chunk => index.TryGetValue((plan.IndexName, chunk.Key), out var stored)
            && stored.Chunk == chunk && stored.Plan.ProjectionId == plan.ProjectionId);

    public bool TryPublish(BuildPlan plan)
    {
        lock (sync)
        {
            if (!IsCurrent(plan) || !Complete(plan)) return false;
            published[(plan.Source.TenantId, plan.Source.DocumentId, plan.IndexName)] = plan;
            return true;
        }
    }

    public bool TryActivate(string tenant, string indexName, string pipeline)
    {
        lock (sync)
        {
            var required = sources.Values.Where(s => s.TenantId == tenant && s.Approved && !s.Deleted).ToArray();
            if (required.Length == 0 || required.Any(s =>
                !published.TryGetValue((tenant, s.DocumentId, indexName), out var p)
                || p.Pipeline != pipeline || !IsCurrent(p) || !Complete(p))) return false;
            routes[tenant] = (indexName, pipeline);
            return true;
        }
    }

    private bool Eligible(string tenant, string group, BuildPlan plan)
    {
        return routes.TryGetValue(tenant, out var route)
            && plan.Source.TenantId == tenant && plan.Source.AllowedGroup == group
            && route.Index == plan.IndexName && route.Pipeline == plan.Pipeline
            && IsCurrent(plan)
            && published.TryGetValue((tenant, plan.Source.DocumentId, plan.IndexName), out var active)
            && active.ProjectionId == plan.ProjectionId;
    }

    public List<Evidence> Read(string tenant, string group)
    {
        lock (sync)
        {
            return index.Values.Where(x => Eligible(tenant, group, x.Plan))
                .OrderBy(x => x.Plan.Source.DocumentId, StringComparer.Ordinal).ThenBy(x => x.Chunk.Ordinal)
                .Select(x => new Evidence(tenant, x.Plan.Source.DocumentId,
                    x.Plan.Source.Version, x.Plan.Source.Revision, x.Plan.IndexName,
                    x.Plan.Pipeline, x.Plan.ProjectionId, x.Chunk.Key, x.Chunk.Text)).ToList();
        }
    }

    public bool CanReuse(string tenant, string group, Evidence evidence)
    {
        lock (sync)
        {
            return index.TryGetValue((evidence.IndexName, evidence.ChunkKey), out var stored)
                && Eligible(tenant, group, stored.Plan)
                && evidence.TenantId == tenant && evidence.DocumentId == stored.Plan.Source.DocumentId
                && evidence.SourceVersion == stored.Plan.Source.Version
                && evidence.SourceRevision == stored.Plan.Source.Revision
                && evidence.Pipeline == stored.Plan.Pipeline
                && evidence.ProjectionId == stored.Plan.ProjectionId
                && evidence.Text == stored.Chunk.Text;
        }
    }

    public void ChangeGroup(string tenant, string document, string group)
    {
        lock (sync)
        {
            if (string.IsNullOrWhiteSpace(group)) throw new ArgumentException("Group required.");
            var old = Current(tenant, document);
            sources[(tenant, document)] = old with { AllowedGroup = group, Revision = old.Revision + 1 };
        }
    }

    public void Delete(string tenant, string document)
    {
        lock (sync)
        {
            var old = Current(tenant, document);
            if (old.Deleted) return;
            sources[(tenant, document)] = old with
            {
                Deleted = true, Approved = false, Revision = old.Revision + 1
            };
        }
    }

    public void Purge(string tenant, string document)
    {
        lock (sync)
        {
            if (!Current(tenant, document).Deleted)
                throw new InvalidOperationException("Tombstone first.");
            foreach (var key in index.Where(x => x.Value.Plan.Source.TenantId == tenant
                && x.Value.Plan.Source.DocumentId == document).Select(x => x.Key).ToArray()) index.Remove(key);
            foreach (var key in published.Keys.Where(k => k.Item1 == tenant && k.Item2 == document).ToArray()) published.Remove(key);
            foreach (var key in bodies.Keys.Where(k => k.Item1 == tenant && k.Item2 == document).ToArray()) bodies.Remove(key);
        }
    }

    public int StoredCount(string tenant, string document)
    {
        lock (sync)
            return index.Values.Count(x => x.Plan.Source.TenantId == tenant && x.Plan.Source.DocumentId == document);
    }
}
