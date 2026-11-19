package report_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestSARIFContract(t *testing.T) {
	var out bytes.Buffer
	if err := writeFixture(&out, "sarif", sample()); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != "2.1.0" {
		t.Fatal("wrong version")
	}
	run := got["runs"].([]any)[0].(map[string]any)
	if run["columnKind"] != "unicodeCodePoints" {
		t.Fatal("wrong columns")
	}
	if want := []any{"\r\n", "\n", "\r"}; !reflect.DeepEqual(run["newlineSequences"], want) {
		t.Fatalf("newline sequences = %v, want %v", run["newlineSequences"], want)
	}
	result := run["results"].([]any)[0].(map[string]any)
	if result["level"] != "error" || result["properties"].(map[string]any)["severity"] != "critical" {
		t.Fatal("lost exact severity")
	}
	loc := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	uri := loc["artifactLocation"].(map[string]any)["uri"].(string)
	if bytes.Contains([]byte(uri), []byte(" ")) || !bytes.Contains([]byte(uri), []byte("%20")) {
		t.Fatal("URI not escaped")
	}
	if result["partialFingerprints"].(map[string]any)["occurrence/v1"] != "occurrence" {
		t.Fatal("fingerprint lost")
	}
}

func TestTerminalEscapesUntrustedPaths(t *testing.T) {
	r := sample()
	r.Findings[0].Location.Path = "unsafe\x1b[31m\npath"
	var out bytes.Buffer
	if err := writeFixture(&out, "terminal", r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte{0x1b}) {
		t.Fatal("terminal escape injected")
	}
}

func TestFormats(t *testing.T) {
	for _, f := range []string{"terminal", "json", "sarif", "markdown"} {
		var out bytes.Buffer
		if err := writeFixture(&out, f, sample()); err != nil || out.Len() == 0 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if err := writeFixture(&bytes.Buffer{}, "bogus", sample()); err == nil {
		t.Fatal("invalid format accepted")
	}
}

func TestHookEventRetainedInReportFormats(t *testing.T) {
	r := sample()
	r.Findings[0].Location.HookEvent = "PreToolUse"
	for _, format := range []string{"terminal", "markdown", "json", "sarif"} {
		var out bytes.Buffer
		if err := writeFixture(&out, format, r); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !bytes.Contains(out.Bytes(), []byte("PreToolUse")) {
			t.Fatalf("%s omitted the hook event", format)
		}
	}
}

func TestTraceFormats(t *testing.T) {
	r := sample()
	loc := r.Findings[0].Location
	r.Findings[0].Trace = []report.TraceStep{{Role: "source", Location: loc}, {Role: "sink", Location: loc}}
	var out bytes.Buffer
	if err := writeFixture(&out, "sarif", r); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	result := parsed["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	flows := result["codeFlows"].([]any)
	locations := flows[0].(map[string]any)["threadFlows"].([]any)[0].(map[string]any)["locations"].([]any)
	if len(locations) != 2 || locations[0].(map[string]any)["kinds"].([]any)[0] != "source" || locations[1].(map[string]any)["kinds"].([]any)[0] != "sink" {
		t.Fatal("lost SARIF flow")
	}
	out.Reset()
	if err := writeFixture(&out, "terminal", r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("source:")) || !bytes.Contains(out.Bytes(), []byte("sink:")) {
		t.Fatal("terminal lost flow")
	}
}

func TestSARIFBOMInDerivedTraceAndDiagnostics(t *testing.T) {
	analysis := sample()
	const virtual = "scout-object://example/member.txt"
	analysis.Extraction.Objects = []report.DerivedObject{{
		File: report.File{Path: virtual, Kind: "text", UTF8BOM: true},
	}}
	analysis.Findings[0].Trace = []report.TraceStep{
		{Role: "source", Location: report.Location{
			Path: virtual, ByteStart: 3, ByteEnd: 7,
			StartLine: 1, StartColumn: 2, EndLine: 2, EndColumn: 2,
		}},
		{Role: "sink", Location: report.Location{
			Path: virtual, ByteStart: 6, ByteEnd: 7,
			StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 2,
		}},
	}
	analysis.Diagnostics = []report.Diagnostic{
		{Path: virtual, Line: 1, Column: 2},
		{Path: virtual, Line: 1, Column: 1},
	}

	var out bytes.Buffer
	if err := writeFixture(&out, "sarif", analysis); err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	flows := result["codeFlows"].([]any)[0].(map[string]any)["threadFlows"].([]any)
	steps := flows[0].(map[string]any)["locations"].([]any)
	invocation := run["invocations"].([]any)[0].(map[string]any)
	notes := invocation["toolExecutionNotifications"].([]any)

	assertSARIFRegion(t, steps[0].(map[string]any)["location"], map[string]any{
		"startLine": float64(1), "startColumn": float64(1), "endLine": float64(2), "endColumn": float64(2),
	})
	assertSARIFRegion(t, steps[1].(map[string]any)["location"], map[string]any{
		"startLine": float64(2), "startColumn": float64(1), "endLine": float64(2), "endColumn": float64(2),
	})
	assertSARIFRegion(t, notes[0].(map[string]any)["locations"].([]any)[0], map[string]any{
		"startLine": float64(1), "startColumn": float64(1),
	})
	assertSARIFRegion(t, notes[1].(map[string]any)["locations"].([]any)[0], map[string]any{
		"byteOffset": float64(0), "byteLength": float64(3),
	})
}

func assertSARIFRegion(t *testing.T, location any, want map[string]any) {
	t.Helper()
	got := location.(map[string]any)["physicalLocation"].(map[string]any)["region"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SARIF region = %v, want %v", got, want)
	}
}

func TestBinaryByteLocations(t *testing.T) {
	r := sample()
	r.Artifact.Files[0].Kind = "binary"
	r.Findings[0].Location.Coordinates = "bytes"
	r.Findings[0].Location.ByteStart = 4
	r.Findings[0].Location.ByteEnd = 20
	r.Findings[0].Location.StartLine = 0
	r.Findings[0].Location.StartColumn = 0
	var out bytes.Buffer
	if err := writeFixture(&out, "sarif", r); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	run := parsed["runs"].([]any)[0].(map[string]any)
	if _, exists := run["columnKind"]; exists {
		t.Error("a binary-only run must omit columnKind")
	}
	result := run["results"].([]any)[0].(map[string]any)
	reg := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
	if reg["byteOffset"] != float64(4) || reg["byteLength"] != float64(16) {
		t.Fatalf("bad byte range: %+v", reg)
	}
	if _, exists := reg["startLine"]; exists {
		t.Fatal("binary result fabricates line coordinates")
	}
	out.Reset()
	if err := writeFixture(&out, "terminal", r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("bytes[4:20]")) {
		t.Fatal("terminal lost byte range")
	}
}

func TestMarkdownEscapesHostilePaths(t *testing.T) {
	r := sample()
	r.Findings[0].Location.Path = "</code><img src=x onerror=alert(1)>`\n[click](https://example.invalid)\x1b[31m"
	var b bytes.Buffer
	if err := writeFixture(&b, "markdown", r); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\x1b", "\n[click]"} {
		if bytes.Contains(b.Bytes(), []byte(unsafe)) {
			t.Fatalf("unsafe report path: %q", unsafe)
		}
	}
	if !bytes.Contains(b.Bytes(), []byte("Location: ``</code><img src=x onerror=alert(1)>`\\n[click](https://example.invalid)\\x1b[31m``,")) {
		t.Fatal("hostile markup escaped the enclosing code span")
	}
}

func sample() report.Analysis {
	return report.Analysis{
		SchemaVersion: "0.1",
		EngineVersion: "test",
		Profile:       "test",
		Artifact: report.Artifact{Files: []report.File{{
			Path: "a b/данные.md",
			Kind: "text",
		}}},
		Coverage: report.Coverage{Completeness: report.Complete},
		Rules: []report.Rule{{
			ID:       "R",
			Version:  "1",
			Severity: report.Critical,
			Title:    "Risk",
		}},
		Findings: []report.Finding{{
			ID:       "occurrence",
			RuleID:   "R",
			Severity: report.Critical,
			Message:  "Risk",
			Location: report.Location{
				Path:        "a b/данные.md",
				ByteStart:   0,
				ByteEnd:     1,
				StartLine:   1,
				StartColumn: 1,
				EndLine:     1,
				EndColumn:   2,
			},
		}},
	}
}

func TestSARIFMessagesEscapeLiteralBraces(t *testing.T) {
	analysis := sample()
	const literal = "Example {0} includes {literal} and }"
	analysis.Findings[0].Message = literal
	analysis.Diagnostics = []report.Diagnostic{{Code: "test_notice", Message: literal}}
	var out bytes.Buffer
	if err := writeFixture(&out, "sarif", analysis); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string
				}
			}
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Message struct {
						Text string
					}
				}
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	const want = "Example {{0}} includes {{literal}} and }}"
	if got := run.Results[0].Message.Text; got != want {
		t.Fatalf("result message = %q, want %q", got, want)
	}
	if got := run.Invocations[0].ToolExecutionNotifications[0].Message.Text; !bytes.HasSuffix([]byte(got), []byte(want)) {
		t.Fatalf("notification message = %q, want suffix %q", got, want)
	}
}

func TestHumanApprovalSummaryKeepsTargetAndFindingSeparate(t *testing.T) {
	run := runFixture()
	run.Targets[0].ID = "a\x00b"
	run.Targets[0].Analysis.Findings = run.Targets[0].Analysis.Findings[:1]
	run.Targets[0].Analysis.Findings[0].ID = "c"
	other := runFixture().Targets[0]
	other.ID, other.Index = "a", 1
	other.Analysis.Findings = other.Analysis.Findings[:1]
	other.Analysis.Findings[0].ID = "b\x00c"
	run.Targets = append(run.Targets, other)
	sealed, err := report.SealRun(run)
	if err != nil {
		t.Fatal(err)
	}
	document := report.NewDocument(sealed, report.Evaluation{
		Decision: report.Block, RunDigest: sealed.Digest,
		Suppressed: []report.Suppression{{TargetID: "a\x00b", FindingID: "c"}},
	})
	for _, format := range []report.Format{report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, document); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Operator-approved occurrences: 1;") || strings.Count(out.String(), "Operator approved") != 1 {
			t.Fatalf("%s attributed an approval to another target: %s", format, &out)
		}
	}
}

func TestEnvironmentEvidenceKeepsTargetAndPathSeparate(t *testing.T) {
	firstHash, secondHash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	run := runFixture()
	run.Targets[0].ID = "a\x00b"
	run.Targets[0].Analysis.Artifact.Files = []report.File{{Path: "c", Size: 1, SHA256: firstHash, Status: report.CaptureCaptured}}
	other := runFixture().Targets[0]
	other.ID, other.Index = "a", 1
	other.Analysis.Artifact.Files = []report.File{{Path: "b\x00c", Size: 1, SHA256: secondHash, Status: report.CaptureCaptured}}
	run.Targets = append(run.Targets, other)
	run.Environment = &report.EnvironmentReport{
		Schema: "scout.environment-analysis/v1", Completeness: report.Complete, MaxObservations: 1, MaxOperations: 1,
		Observations: []report.EnvironmentObservation{{ID: "collision", Kind: "mcp_name_collision", Evidence: []report.EnvironmentEvidence{
			{TargetID: "a\x00b", Role: "mcp_identifier", Source: report.SourceRef{Path: "c", SHA256: firstHash, ByteEnd: 1, SpanSHA256: firstHash}},
			{TargetID: "a", Role: "mcp_identifier", Source: report.SourceRef{Path: "b\x00c", SHA256: secondHash, ByteEnd: 1, SpanSHA256: secondHash}},
		}}},
	}
	if _, err := report.SealRun(run); err != nil {
		t.Errorf("distinct qualified files collided: %v", err)
	}
	// The first reference must not borrow the second target's captured hash.
	run.Environment.Observations[0].Evidence[0].Source.SHA256 = secondHash
	if _, err := report.SealRun(run); err == nil {
		t.Error("evidence from another target's file passed the qualified inventory check")
	}
}
