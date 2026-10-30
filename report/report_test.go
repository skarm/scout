package report_test

import (
	"bytes"
	"encoding/json"
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
	result := parsed["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
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
