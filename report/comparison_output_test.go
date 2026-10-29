package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestComparisonDocumentEscapesAndKeepsCandidate(t *testing.T) {
	d := comparisonDocument(t)
	for _, format := range []report.Format{report.Text, report.Markdown, report.JSON, report.SARIF} {
		var out bytes.Buffer
		if err := report.Write(&out, format, d); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), []byte{0x1b}) || (format != report.Text && strings.Contains(out.String(), "<script>")) {
			t.Fatal(format, "output injection")
		}
		if !strings.Contains(out.String(), "block") {
			t.Fatal("candidate verdict missing")
		}
		if (format == report.JSON || format == report.SARIF) && !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON")
		}
		if err := report.Write(updateFailWriter{}, format, d); err == nil {
			t.Fatal("writer failure ignored")
		}
	}
}

type updateFailWriter struct{}

func (updateFailWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func comparisonDocument(t *testing.T) report.Document {
	t.Helper()
	bad := "<script>alert(1)</script>\x1b[31m\n![x](https://e.invalid)"
	base := sample()
	base.Findings[0].Location.Path = bad
	run, err := report.SealRun(report.Run{
		Operation: report.CompareOperation, State: report.RunComplete,
		Targets: []report.TargetResult{{
			ID:       "before",
			Index:    0,
			Role:     "before",
			State:    report.RunComplete,
			Analysis: base,
		}, {
			ID:       "after",
			Index:    1,
			Role:     "after",
			State:    report.RunComplete,
			Analysis: base,
		}},
		Comparison: &report.UpdateDelta{
			Completeness: report.Complete,
			Files: []report.FileChange{{
				ObjectID: "x",
				Address:  report.ObjectAddress{Root: bad},
				Change:   "modified",
				Before:   &report.File{Path: bad},
				After:    &report.File{Path: bad},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return report.NewDocument(run, report.Evaluation{
		Decision:     report.Block,
		RunDigest:    run.Digest,
		PolicyDigest: "fixture-policy",
	})
}
