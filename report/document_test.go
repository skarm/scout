package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestParseDocumentFormats(t *testing.T) {
	for _, want := range []report.Format{report.Text, report.JSON, report.SARIF, report.Markdown} {
		got, err := report.ParseFormat(string(want))
		if err != nil || got != want {
			t.Fatalf("format %q: %q %v", want, got, err)
		}
	}
	for _, value := range []string{"", "terminal", "JSON", "unknown"} {
		if _, err := report.ParseFormat(value); err == nil {
			t.Fatalf("invalid format %q accepted", value)
		}
	}
}

func TestWriteDocumentJSONRoundTrip(t *testing.T) {
	document := documentFixture(t, false)
	var out bytes.Buffer
	if err := report.Write(&out, report.JSON, document); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&out)
	var decoded report.Document
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil || decoded.Schema != report.DocumentSchema || len(decoded.Run.Targets) != 2 || decoded.Evaluation.Decision != report.Block {
		t.Fatalf("document contract lost: %+v %v", decoded, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("stdout contained more than one document: %v", err)
	}
}

func TestDocumentSARIFRetainsEvidenceFailuresAndApprovals(t *testing.T) {
	document := documentFixture(t, true)
	var out bytes.Buffer
	if err := report.Write(&out, report.SARIF, document); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version    string `json:"version"`
		Properties struct {
			RunState  report.State `json:"runState"`
			RunDigest string       `json:"runDigest"`
		} `json:"properties"`
		Runs []struct {
			Tool struct {
				Driver struct {
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				Successful bool `json:"executionSuccessful"`
			} `json:"invocations"`
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Status string `json:"status"`
				} `json:"suppressions"`
				Properties struct {
					Evidence report.Evidence `json:"evidence"`
				} `json:"properties"`
				Locations []struct {
					Physical struct {
						Region struct {
							ByteOffset int `json:"byteOffset"`
							ByteLength int `json:"byteLength"`
							StartLine  int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "2.1.0" || len(got.Runs) != 2 || got.Properties.RunState != report.RunIncomplete || got.Properties.RunDigest != document.Run.Digest {
		t.Fatalf("missing run contract: %+v", got)
	}
	for _, run := range got.Runs {
		if run.Tool.Driver.Version != document.Run.Engine.Version {
			t.Fatal("SARIF tool version does not come from the supplied run")
		}
		if len(run.Invocations) != 1 || run.Invocations[0].Successful {
			t.Fatal("incomplete overall run reported as successful invocation")
		}
	}
	first := got.Runs[0].Results
	if len(first) != 1 || first[0].RuleID != "R" || first[0].Properties.Evidence.SpanSHA256 != "derived-span" || len(first[0].Suppressions) != 1 || first[0].Suppressions[0].Status != "accepted" {
		t.Fatalf("evidence or matching approval lost: %+v", first)
	}
	if len(first[0].Locations) != 1 {
		t.Fatal("missing derived evidence location")
	}
	region := first[0].Locations[0].Physical.Region
	if region.ByteOffset != 4 || region.ByteLength != 6 || region.StartLine != 0 {
		t.Fatalf("derived binary evidence acquired fabricated coordinates: %+v", region)
	}
	if len(got.Runs[1].Results) != 1 || len(got.Runs[1].Results[0].Suppressions) != 0 {
		t.Fatal("approval applied to an unrelated finding")
	}
}

func TestHumanDocumentsQuoteLabelsAndDoNotMutateInput(t *testing.T) {
	document := documentFixture(t, false)
	document.Run.Targets[0].Label = "</code><img src=x>`\n\x1b[31m"
	before, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []report.Format{report.Text, report.Markdown, report.SARIF} {
		var out bytes.Buffer
		if err := report.Write(&out, format, document); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if bytes.Contains(out.Bytes(), []byte{0x1b}) {
			t.Fatalf("unsafe label in %s", format)
		}
		if format == report.Markdown && !strings.Contains(out.String(), "Target 0: ``</code><img src=x>`\\n\\x1b[31m``;") {
			t.Fatal("label escaped its Markdown code span")
		}
		if format != report.SARIF && (!strings.Contains(out.String(), "Target 0") || !strings.Contains(out.String(), "Target 1")) {
			t.Fatalf("missing target in %s", format)
		}
	}
	after, err := json.Marshal(document)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rendering changed source document: %v", err)
	}
}

func TestDocumentWritersRejectInvalidBindingBeforeOutput(t *testing.T) {
	document := documentFixture(t, false)
	document.Evaluation.RunDigest = "another-run"
	for _, format := range []report.Format{report.Text, report.JSON, report.SARIF, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, document); err == nil || out.Len() != 0 {
			t.Fatalf("invalid binding emitted output in %s: %v", format, err)
		}
	}
}

func TestDocumentWritersPropagateFailure(t *testing.T) {
	document := documentFixture(t, false)
	broken := errors.New("document pipe closed")
	for _, format := range []report.Format{report.Text, report.JSON, report.SARIF, report.Markdown} {
		if err := report.Write(documentWriterFailure{err: broken}, format, document); !errors.Is(err, broken) {
			t.Fatalf("%s lost writer failure: %v", format, err)
		}
		if err := report.WriteFailure(documentWriterFailure{err: broken}, format, report.ScanOperation, report.Problem{
			Code:  "invalid_config",
			Phase: "configuration",
		}); !errors.Is(err, broken) {
			t.Fatalf("failure %s lost writer failure: %v", format, err)
		}
	}
}

func TestWriteFailureHasNoInventedRunOrRawError(t *testing.T) {
	problem := report.Problem{
		Code:     "invalid_config",
		Phase:    "configuration",
		TargetID: "target\n\x1b[31m",
		Message:  "SECRET_RAW_PROVIDER_ERROR",
	}
	for _, format := range []report.Format{report.Text, report.JSON, report.SARIF, report.Markdown} {
		var out bytes.Buffer
		if err := report.WriteFailure(&out, format, report.ScanOperation, problem); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if strings.Contains(out.String(), "SECRET_RAW_PROVIDER_ERROR") || bytes.Contains(out.Bytes(), []byte{0x1b}) {
			t.Fatalf("failure leaked raw error or terminal control in %s", format)
		}
		if format == report.JSON {
			if !strings.Contains(out.String(), `"run": null`) || !strings.Contains(out.String(), `"evaluation": null`) {
				t.Fatal("preflight failure does not explicitly identify absent execution/evaluation")
			}
			var failure struct {
				Schema     string             `json:"schema"`
				Operation  report.Operation   `json:"operation"`
				Run        *report.Run        `json:"run"`
				Evaluation *report.Evaluation `json:"evaluation"`
				Problems   []report.Problem   `json:"problems"`
			}
			if err := json.Unmarshal(out.Bytes(), &failure); err != nil || failure.Schema != report.DocumentSchema || failure.Operation != report.ScanOperation || failure.Run != nil || failure.Evaluation != nil || len(failure.Problems) != 1 || failure.Problems[0].Code != "invalid_config" {
				t.Fatalf("invalid failure envelope: %s %v", out.String(), err)
			}
		}
		if format == report.SARIF && (!strings.Contains(out.String(), `"executionSuccessful": false`) || !strings.Contains(out.String(), `"runState": "failed"`)) {
			t.Fatal("SARIF failure was not recorded")
		}
	}
}

func TestDocumentWritersRejectInvalidFormatsAndShortWrites(t *testing.T) {
	document := documentFixture(t, false)
	var out bytes.Buffer
	if err := report.Write(&out, "unknown", document); err == nil || out.Len() != 0 {
		t.Fatalf("unsupported format wrote output: %v", err)
	}
	for _, format := range []report.Format{report.Text, report.JSON, report.SARIF, report.Markdown} {
		if err := report.Write(shortDocumentWriter{}, format, document); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("%s ignored short write: %v", format, err)
		}
		if err := report.Write(nil, format, document); err == nil {
			t.Fatalf("%s accepted nil writer", format)
		}
	}
}

func TestFailureProblemCodeBoundary(t *testing.T) {
	for _, code := range []string{"", strings.Repeat("a", 129), "UPPER", "space here", "dash-code", "é"} {
		var out bytes.Buffer
		if err := report.WriteFailure(&out, report.JSON, report.ScanOperation, report.Problem{
			Code:  code,
			Phase: "initialize",
		}); err == nil || out.Len() != 0 {
			t.Fatalf("invalid problem code accepted: %q", code)
		}
	}
	var out bytes.Buffer
	if err := report.WriteFailure(&out, report.JSON, report.ScanOperation, report.Problem{
		Code:  "1_valid_code",
		Phase: "initialize",
	}); err != nil {
		t.Fatal(err)
	}
}

type shortDocumentWriter struct{}

func (shortDocumentWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type documentWriterFailure struct{ err error }

func (w documentWriterFailure) Write([]byte) (int, error) { return 0, w.err }

func documentFixture(t *testing.T, incomplete bool) report.Document {
	t.Helper()
	first := sample()
	first.Findings[0].ID = "derived-occurrence"
	first.Findings[0].Evidence = report.Evidence{FileSHA256: "derived-file", SpanSHA256: "derived-span"}
	first.Findings[0].Location = report.Location{
		Path:        "scout-object:/archive/member.bin",
		Coordinates: "bytes",
		Derived:     true,
		ByteStart:   4,
		ByteEnd:     10,
	}
	first.Extraction.Objects = []report.DerivedObject{{File: report.File{
		Path: first.Findings[0].Location.Path,
		Kind: "binary",
	}}}
	run := report.Run{
		Operation: report.ScanOperation, State: report.RunComplete,
		Engine: report.EngineIdentity{Version: "fixture", RulepackDigest: "rules"},
		Targets: []report.TargetResult{{
			ID:       "target-0",
			Index:    0,
			Label:    "first",
			State:    report.RunComplete,
			Analysis: first,
		}, {
			ID:       "target-1",
			Index:    1,
			Label:    "second",
			State:    report.RunComplete,
			Analysis: sample(),
		}},
	}
	if incomplete {
		run.State, run.Targets[0].State = report.RunIncomplete, report.RunIncomplete
		run.Targets[0].Analysis.Coverage.Completeness = report.Partial
	}
	sealed, err := report.SealRun(run)
	if err != nil {
		t.Fatal(err)
	}
	return report.NewDocument(sealed, report.Evaluation{
		Decision:     report.Block,
		RunDigest:    sealed.Digest,
		PolicyDigest: "policy",
		Reasons:      []string{"severity_threshold"},
		Suppressed: []report.Suppression{{
			FindingID: "derived-occurrence",
			Kind:      "fingerprint",
		}, {FindingID: "unrelated"}},
	})
}
