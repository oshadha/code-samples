// Practical .NET AI Engineering: Multimodal Document Processing
// Target: .NET 8 or later; no third-party packages.
// Copy this file over Program.cs in a new console project, then: dotnet run
// Synthetic extraction fixtures only. No PDF parser, OCR, model, HTTP server,
// persistent store, authentication, or production approval workflow is included.
// Authenticated tenant selection and immutable server-owned snapshots are assumed.
// Expected outcomes are assertions, not claims that this file was run by its author.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

public static class Program
{
    public static void Main() => Checks.Run();
}

// snippet:identity
public sealed record SourceVersion(string TenantId, string DocumentId,
    long Revision, string ContentHash);
public sealed record PipelineVersion(string Renderer, string Extractor,
    string Prompt, string Schema);
public static class Hashing
{
    public static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes));
    public static string Of<T>(T value) =>
        Sha256(JsonSerializer.SerializeToUtf8Bytes(value));
}
// end:identity

public enum Route { NativeText, Layout, Review }
public enum PageStatus { Pending, Succeeded, Failed }
public enum Outcome { ReadyForReview, NeedsReview, Incomplete, Invalid, Obsolete }

// snippet:routing
public sealed record PageProbe(int Page, bool NativeTextUsable,
    bool HasTable, bool HasVisualOnlyContent, bool RenderSucceeded);
public static class Router
{
    public static Route Choose(PageProbe page)
    {
        if (!page.RenderSucceeded) return Route.Review;
        if (page.HasTable || page.HasVisualOnlyContent) return Route.Layout;
        return page.NativeTextUsable ? Route.NativeText : Route.Layout;
    }
}
// end:routing

// snippet:budget
public sealed class PageBudget(int limit)
{
    private readonly object sync = new();
    private int reserved;
    public bool TryReserve(int pages)
    {
        if (pages <= 0) throw new ArgumentOutOfRangeException(nameof(pages));
        lock (sync)
        {
            if (limit <= 0 || pages > limit - reserved) return false;
            reserved += pages;
            return true;
        }
    }
}
// end:budget

// snippet:geometry
public sealed record Box(double X, double Y, double Width, double Height)
{
    public bool IsNormalized => double.IsFinite(X) && double.IsFinite(Y)
        && double.IsFinite(Width) && double.IsFinite(Height)
        && X >= 0 && Y >= 0 && Width > 0 && Height > 0
        && X + Width <= 1 && Y + Height <= 1;
    public static Box Normalize(Box raw, double pageWidth, double pageHeight)
    {
        if (!double.IsFinite(pageWidth) || !double.IsFinite(pageHeight)
            || pageWidth <= 0 || pageHeight <= 0)
            throw new ArgumentException("Invalid page dimensions.");
        var result = new Box(raw.X / pageWidth, raw.Y / pageHeight,
            raw.Width / pageWidth, raw.Height / pageHeight);
        return result.IsNormalized ? result
            : throw new ArgumentException("Region is outside the page.");
    }
}
// end:geometry

// snippet:cells
public sealed record Cell(string Id, SourceVersion Source, string RunId,
    int Page, string TableId, int Row, int Column,
    int RowSpan, int ColumnSpan, string Text, Box Region);
public sealed record PageResult(int Page, Route Route, PageStatus Status,
    bool RequiresReview);
public sealed record Signal(int Page, string Description, int? NoticeHours,
    bool Uncertain);
public sealed record Packet(SourceVersion Source, PipelineVersion Pipeline,
    string RunId, int PageCount, PageResult[] Pages, Cell[] Cells,
    Signal[] Signals);
// end:cells

// snippet:contract
public sealed record Candidate
{
    public required int SpecialistNoticeHours { get; init; }
    public required string ValueCellId { get; init; }
    public required string Quote { get; init; }
}
public static class CandidateReader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
// end:contract

    // snippet:parse
    public static Candidate Parse(string json)
    {
        if (json.Length > 4096) throw new JsonException("Response too large.");
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("Expected an object.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in doc.RootElement.EnumerateObject())
            if (!names.Add(property.Name)) throw new JsonException("Duplicate key.");
        var value = JsonSerializer.Deserialize<Candidate>(json, Options)
            ?? throw new JsonException("Missing candidate.");
        if (value.SpecialistNoticeHours is < 1 or > 720
            || string.IsNullOrWhiteSpace(value.ValueCellId)
            || string.IsNullOrWhiteSpace(value.Quote))
            throw new JsonException("Invalid candidate values.");
        return value;
    }
    // end:parse
}

public sealed record Verdict(Outcome Outcome, string Reason, int? Hours = null,
    string? ReviewFingerprint = null);

public static class Gate
{
    // snippet:coverage
    public static bool HasCompleteCoverage(Packet packet)
    {
        if (packet.PageCount is < 1 or > 100
            || packet.Pages.Length != packet.PageCount) return false;
        return packet.Pages.All(p => p.Status == PageStatus.Succeeded)
            && packet.Pages.Select(p => p.Page).OrderBy(p => p)
                .SequenceEqual(Enumerable.Range(1, packet.PageCount));
    }
    // end:coverage

    // snippet:current
    public static bool IsCurrent(Packet packet, SourceVersion current,
        PipelineVersion expected, bool deleted) =>
        !deleted && packet.Source == current && packet.Pipeline == expected;
    // end:current

    public static bool HasValidStructure(Packet packet)
    {
        if (string.IsNullOrWhiteSpace(packet.RunId)
            || packet.Cells.Length > 10_000 || packet.Signals.Length > 1000)
            return false;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var positions = new HashSet<(int, string, int, int)>();
        foreach (var cell in packet.Cells)
        {
            if (cell.Source != packet.Source || cell.RunId != packet.RunId
                || string.IsNullOrWhiteSpace(cell.Id) || !ids.Add(cell.Id)
                || string.IsNullOrWhiteSpace(cell.TableId)
                || cell.Page < 1 || cell.Page > packet.PageCount
                || cell.Row < 0 || cell.Column < 0
                || cell.RowSpan < 1 || cell.ColumnSpan < 1
                || !cell.Region.IsNormalized || cell.Text is null
                || !positions.Add((cell.Page, cell.TableId, cell.Row, cell.Column)))
                return false;
        }
        return packet.Signals.All(s => s.Page >= 1 && s.Page <= packet.PageCount);
    }

    // snippet:resolve
    public static Cell? Resolve(Packet packet, Candidate candidate)
    {
        var matches = packet.Cells.Where(c => c.Id == candidate.ValueCellId)
            .ToArray();
        if (matches.Length != 1) return null;
        var cell = matches[0];
        return cell.Source == packet.Source && cell.RunId == packet.RunId
            && cell.Text == candidate.Quote ? cell : null;
    }
    // end:resolve

    private static Cell? At(Packet packet, Cell cell, int row, int column) =>
        packet.Cells.SingleOrDefault(c => c.Page == cell.Page
            && c.TableId == cell.TableId && c.Row == row && c.Column == column);

    // snippet:table
    public static int? ReadSpecialistHours(Packet packet, Cell cell)
    {
        var table = packet.Cells.Where(c => c.Page == cell.Page
            && c.TableId == cell.TableId).ToArray();
        if (table.Any(c => c.RowSpan != 1 || c.ColumnSpan != 1)
            || cell.Row == 0 || cell.Column != 1) return null;
        if (At(packet, cell, 0, 0)?.Text != "Consultation type"
            || At(packet, cell, 0, 1)?.Text != "Minimum notice"
            || At(packet, cell, cell.Row, 0)?.Text != "Specialist") return null;
        const string suffix = " hours";
        if (!cell.Text.EndsWith(suffix, StringComparison.Ordinal)) return null;
        return int.TryParse(cell.Text[..^suffix.Length], NumberStyles.None,
            CultureInfo.InvariantCulture, out int hours) && hours is >= 1 and <= 720
                ? hours : null;
    }
    // end:table

    // snippet:conflicts
    public static bool HasUnresolvedEvidence(Packet packet, int hours)
    {
        if (packet.Pages.Any(p => p.RequiresReview || p.Route == Route.Review)
            || packet.Signals.Any(s => s.Uncertain
                || (s.NoticeHours is int h && h != hours))) return true;
        foreach (var label in packet.Cells.Where(c =>
            c.Column == 0 && c.Row > 0 && c.Text == "Specialist"))
        {
            var value = At(packet, label, label.Row, 1);
            if (value is null || ReadSpecialistHours(packet, value) != hours)
                return true;
        }
        return false;
    }
    // end:conflicts

    // snippet:evaluate
    public static Verdict Evaluate(Packet packet, Candidate candidate,
        SourceVersion current, PipelineVersion expected, bool deleted = false)
    {
        if (!IsCurrent(packet, current, expected, deleted))
            return new(Outcome.Obsolete, "Source or pipeline is no longer current.");
        if (!HasCompleteCoverage(packet))
            return new(Outcome.Incomplete, "Required pages are missing or unfinished.");
        if (!HasValidStructure(packet))
            return new(Outcome.Invalid, "Evidence structure or scope is invalid.");
        var cell = Resolve(packet, candidate);
        if (cell is null) return new(Outcome.Invalid, "Citation or quote mismatch.");
        var hours = ReadSpecialistHours(packet, cell);
        if (hours is null || hours.Value != candidate.SpecialistNoticeHours)
            return new(Outcome.NeedsReview, "Value, unit, or table context disagrees.");
        if (HasUnresolvedEvidence(packet, hours.Value))
            return new(Outcome.NeedsReview, "Uncertainty or conflicting evidence.");
        return new(Outcome.ReadyForReview, "Extraction checks passed; not published.",
            hours.Value, ReviewFingerprint(packet, candidate));
    }
    // end:evaluate

    // snippet:keys
    public static string ArtifactKey(SourceVersion source,
        PipelineVersion pipeline, int page, string stage) =>
        Hashing.Of(new { source, pipeline, page, stage });
    public static string ReviewFingerprint(Packet packet, Candidate candidate) =>
        Hashing.Of(new { packet, candidate });
    // end:keys
}

public static class Fixtures
{
    // These are fixture bytes, not a PDF. Production hashes the original upload.
    public static readonly SourceVersion Source = new("clinic-a", "notice", 7,
        Hashing.Sha256(Encoding.UTF8.GetBytes("synthetic notice packet v7")));
    public static readonly PipelineVersion Pipeline = new(
        "fixture-render-v1", "fixture-layout-v1", "notice-prompt-v1", "notice-v1");
    public const string RunId = "extraction-001";
    public const string GoodJson = """
        {"SpecialistNoticeHours":72,"ValueCellId":"p2-t1-r2-c1","Quote":"72 hours"}
        """;

    public static Packet Packet()
    {
        Cell C(string id, int row, int column, string value) =>
            new(id, Source, RunId, 2, "t1", row, column, 1, 1, value,
                new Box(0.1 + column * 0.4, 0.1 + row * 0.1, 0.35, 0.08));
        return new(Source, Pipeline, RunId, 3,
            [new(1, Route.NativeText, PageStatus.Succeeded, false),
             new(2, Route.Layout, PageStatus.Succeeded, false),
             new(3, Route.Layout, PageStatus.Succeeded, false)],
            [C("p2-t1-r0-c0", 0, 0, "Consultation type"),
             C("p2-t1-r0-c1", 0, 1, "Minimum notice"),
             C("p2-t1-r1-c0", 1, 0, "General"),
             C("p2-t1-r1-c1", 1, 1, "24 hours"),
             C("p2-t1-r2-c0", 2, 0, "Specialist"),
             C("p2-t1-r2-c1", 2, 1, "72 hours")], []);
    }
}

public static class Checks
{
    private static int passed;
    private static void Expect(bool condition, string name)
    {
        if (!condition) throw new Exception("FAIL: " + name);
        passed++;
        Console.WriteLine("PASS: " + name);
    }
    private static void RejectJson(string json, string name)
    {
        try { CandidateReader.Parse(json); }
        catch (JsonException) { Expect(true, name); return; }
        throw new Exception("FAIL: " + name);
    }
    private static void RejectBox(Action action, string name)
    {
        try { action(); }
        catch (ArgumentException) { Expect(true, name); return; }
        throw new Exception("FAIL: " + name);
    }
    private static Packet EditCell(Packet p, string id, Func<Cell, Cell> change) =>
        p with { Cells = p.Cells.Select(c => c.Id == id ? change(c) : c).ToArray() };
    private static Packet EditPage(Packet p, int page, Func<PageResult, PageResult> change) =>
        p with { Pages = p.Pages.Select(x => x.Page == page ? change(x) : x).ToArray() };

    public static void Run()
    {
        var packet = Fixtures.Packet();
        var candidate = CandidateReader.Parse(Fixtures.GoodJson);
        Verdict Evaluate(Packet p, Candidate? c = null) =>
            Gate.Evaluate(p, c ?? candidate, Fixtures.Source, Fixtures.Pipeline);

        Expect(Evaluate(packet).Outcome == Outcome.ReadyForReview, "valid extraction awaits review");
        Expect(Evaluate(packet).Hours == 72, "specialist value is 72");
        Expect(Router.Choose(new(1, true, false, false, true)) == Route.NativeText, "usable native text");
        Expect(Router.Choose(new(2, true, true, false, true)) == Route.Layout, "table overrides text layer");
        Expect(Router.Choose(new(3, false, false, true, true)) == Route.Layout, "scan uses layout");
        Expect(Router.Choose(new(3, true, false, false, false)) == Route.Review, "failed render needs review");

        // snippet:tests
        var missingPage = packet with { Pages = packet.Pages[..2] };
        Expect(Evaluate(missingPage).Outcome == Outcome.Incomplete,
            "missing page cannot disappear");
        var wrongRow = candidate with { SpecialistNoticeHours = 24,
            ValueCellId = "p2-t1-r1-c1", Quote = "24 hours" };
        Expect(Evaluate(packet, wrongRow).Outcome == Outcome.NeedsReview,
            "real citation to wrong row is insufficient");
        var amendment = packet with { Signals =
            [new(3, "Handwritten notice amendment", 48, true)] };
        Expect(Evaluate(amendment).Outcome == Outcome.NeedsReview,
            "unresolved amendment blocks normal review path");
        // end:tests

        var duplicates = packet with { Pages = [packet.Pages[0], packet.Pages[1], packet.Pages[1]] };
        Expect(Evaluate(duplicates).Outcome == Outcome.Incomplete, "duplicate page is not coverage");
        Expect(Evaluate(EditPage(packet, 3, p => p with { Status = PageStatus.Failed })).Outcome
            == Outcome.Incomplete, "failed OCR remains incomplete");
        Expect(Evaluate(EditPage(packet, 3, p => p with { RequiresReview = true })).Outcome
            == Outcome.NeedsReview, "ambiguous visual region triggers review");
        Expect(Evaluate(packet, candidate with { ValueCellId = "invented" }).Outcome
            == Outcome.Invalid, "invented citation rejected");
        Expect(Evaluate(packet, candidate with { Quote = "48 hours" }).Outcome
            == Outcome.Invalid, "fabricated quote rejected");
        Expect(Evaluate(packet, candidate with { SpecialistNoticeHours = 48 }).Outcome
            == Outcome.NeedsReview, "number must agree with source");
        var days = EditCell(packet, candidate.ValueCellId, c => c with { Text = "3 days" });
        Expect(Evaluate(days, candidate with { Quote = "3 days" }).Outcome
            == Outcome.NeedsReview, "no implicit unit conversion");
        var merged = EditCell(packet, candidate.ValueCellId, c => c with { RowSpan = 2 });
        Expect(Evaluate(merged).Outcome == Outcome.NeedsReview, "merged table outside supported shape");
        var header = EditCell(packet, "p2-t1-r0-c1", c => c with { Text = "Price" });
        Expect(Evaluate(header).Outcome == Outcome.NeedsReview, "column meaning validated");
        var foreign = EditCell(packet, candidate.ValueCellId,
            c => c with { Source = c.Source with { TenantId = "clinic-b" } });
        Expect(Evaluate(foreign).Outcome == Outcome.Invalid, "foreign tenant evidence rejected");
        var oldRun = EditCell(packet, candidate.ValueCellId, c => c with { RunId = "old-run" });
        Expect(Evaluate(oldRun).Outcome == Outcome.Invalid, "mixed extraction runs rejected");
        Expect(Evaluate(packet with { Cells = [.. packet.Cells, packet.Cells[0]] }).Outcome
            == Outcome.Invalid, "duplicate evidence ID rejected");
        var samePosition = packet.Cells[0] with { Id = "other-id" };
        Expect(Evaluate(packet with { Cells = [.. packet.Cells, samePosition] }).Outcome
            == Outcome.Invalid, "ambiguous cell coordinates rejected");
        var invalidBox = EditCell(packet, candidate.ValueCellId,
            c => c with { Region = new(double.NaN, 0, 0.1, 0.1) });
        Expect(Evaluate(invalidBox).Outcome == Outcome.Invalid, "NaN geometry rejected");
        Expect(Gate.Evaluate(packet, candidate, Fixtures.Source with { Revision = 8 },
            Fixtures.Pipeline).Outcome == Outcome.Obsolete, "new revision invalidates extraction");
        Expect(Gate.Evaluate(packet, candidate, Fixtures.Source, Fixtures.Pipeline,
            deleted: true).Outcome == Outcome.Obsolete, "deletion invalidates extraction");
        Expect(Gate.Evaluate(packet, candidate, Fixtures.Source,
            Fixtures.Pipeline with { Schema = "v2" }).Outcome == Outcome.Obsolete,
            "schema change invalidates extraction");
        var conflicting = packet with { Signals = [new(3, "Printed amendment", 48, false)] };
        Expect(Evaluate(conflicting).Outcome == Outcome.NeedsReview, "clear conflicting evidence needs review");
        var secondTable = packet.Cells.Select(c => c with { Id = "copy-" + c.Id,
            Page = 3, TableId = "t2", Text = c.Id == candidate.ValueCellId ? "48 hours" : c.Text });
        Expect(Evaluate(packet with { Cells = [.. packet.Cells, .. secondTable] }).Outcome
            == Outcome.NeedsReview, "conflicting table values need review");
        Expect(Evaluate(packet with { Signals = [new(3, "Unclear margin", null, true)] }).Outcome
            == Outcome.NeedsReview, "unreadable evidence is not absence");

        RejectJson("{}", "required JSON properties");
        RejectJson(Fixtures.GoodJson.Replace("72,", "\"72\","), "numeric string rejected");
        RejectJson(Fixtures.GoodJson.Replace("72,", "72.5,"), "fraction rejected");
        RejectJson(Fixtures.GoodJson.Replace("72,", "0,"), "out of range rejected");
        RejectJson(Fixtures.GoodJson.Replace("72,", "72,\"Approved\":true,"), "unknown property rejected");
        RejectJson(Fixtures.GoodJson.Replace("72,", "72,\"SpecialistNoticeHours\":48,"), "duplicate property rejected");
        RejectJson(Fixtures.GoodJson.Replace("\"72 hours\"", "null"), "null quote rejected");
        RejectJson("null", "null response rejected");
        RejectJson("[]", "array response rejected");
        RejectJson(new string(' ', 4097), "oversized response rejected");

        var normalized = Box.Normalize(new(0.85, 1.1, 1.7, 2.2), 8.5, 11);
        Expect(Math.Abs(normalized.X - 0.1) < 0.0001 && normalized.IsNormalized,
            "page coordinate normalization");
        RejectBox(() => Box.Normalize(new(0, 0, 1, 1), 0, 11), "zero page dimension rejected");
        RejectBox(() => Box.Normalize(new(9, 0, 1, 1), 8.5, 11), "out of page region rejected");
        var budget = new PageBudget(3);
        Expect(budget.TryReserve(2) && !budget.TryReserve(2) && budget.TryReserve(1),
            "reservation limit never silently truncates pages");
        var key = Gate.ArtifactKey(Fixtures.Source, Fixtures.Pipeline, 2, "layout");
        Expect(key == Gate.ArtifactKey(Fixtures.Source, Fixtures.Pipeline, 2, "layout"),
            "same inputs have stable artifact key");
        Expect(key != Gate.ArtifactKey(Fixtures.Source with { TenantId = "clinic-b" },
            Fixtures.Pipeline, 2, "layout"), "artifact key includes tenant");
        Expect(key != Gate.ArtifactKey(Fixtures.Source, Fixtures.Pipeline with { Renderer = "v2" },
            2, "layout"), "artifact key includes renderer");
        Expect(Gate.ReviewFingerprint(packet, candidate) != Gate.ReviewFingerprint(amendment, candidate),
            "amendment changes review fingerprint");
        Console.WriteLine($"\n{passed} checks passed. Synthetic fixtures only; no provider calls.");
    }
}
