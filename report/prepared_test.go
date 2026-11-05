package report_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestPreparedComparisonRestoresOperationAfterJSONRoundTrip(t *testing.T) {
	document := comparisonDocument(t)
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	var decoded report.Document
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	prepared, err := report.Prepare(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Snapshot().Run.Operation != report.CompareOperation || decoded.Run.Operation != "" {
		t.Error("preparation did not restore the snapshot's operation independently of the caller")
	}

	for _, format := range []report.Format{report.Text, report.Markdown} {
		var original, roundTrip bytes.Buffer
		if err := report.Write(&original, format, document); err != nil {
			t.Fatal(err)
		}
		if err := prepared.Write(&roundTrip, format); err != nil {
			t.Fatal(err)
		}
		if strings.Index(roundTrip.String(), "Target 1:") > strings.Index(roundTrip.String(), "Target 0:") {
			t.Errorf("%s moved the candidate after the previous version following JSON decoding", format)
		}
		if !bytes.Equal(original.Bytes(), roundTrip.Bytes()) {
			t.Errorf("%s changed after JSON decoding and preparation", format)
		}
	}
}

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
