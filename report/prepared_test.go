package report_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/skarm/scout/report"
)

func TestPreparedDocumentOwnsSnapshotAcrossOutputs(t *testing.T) {
	document := documentFixture(t, false)
	prepared, err := report.Prepare(document)
	if err != nil {
		t.Fatal(err)
	}
	document.Run.Targets[0].Analysis.Findings[0].Message = "mutated"
	document.Evaluation.Reasons[0] = "mutated"
	snapshot := prepared.Snapshot()
	snapshot.Run.Targets[0].Analysis.Findings[0].Message = "snapshot-mutated"
	snapshot.Evaluation.Reasons[0] = "snapshot-mutated"
	for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := prepared.Write(&out, format); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), []byte("mutated")) {
			t.Fatal("immutable prepared report aliases caller data")
		}
	}
}

func TestPreparedDocumentRejectsCorruptionAndZeroValue(t *testing.T) {
	document := documentFixture(t, false)
	document.Run.Targets[0].Analysis.Findings[0].Message = "altered"
	if _, err := report.Prepare(document); err == nil {
		t.Fatal("corrupt document accepted")
	}
	var empty report.PreparedDocument
	var out bytes.Buffer
	if err := empty.Write(&out, report.JSON); err == nil || out.Len() != 0 {
		t.Fatal("zero prepared document emitted data")
	}
}

func BenchmarkPreparedFormats(b *testing.B) {
	run := benchmarkRun(b, 5000)
	document := report.NewDocument(run, report.Evaluation{RunDigest: run.Digest, Decision: report.Block})
	prepared, err := report.Prepare(document)
	if err != nil {
		b.Fatal(err)
	}
	for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
		b.Run(string(format), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := prepared.Write(io.Discard, format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
