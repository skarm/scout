package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestLegacySuppressionTargetsAreResolvedWithoutMutatingTheCaller(t *testing.T) {
	document := documentFixture(t, false)
	prepared, err := report.Prepare(document)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.Snapshot()
	if resolved.Evaluation.Suppressed[0].TargetID != document.Run.Targets[0].ID {
		t.Fatal("unique legacy occurrence did not acquire its target")
	}
	if document.Evaluation.Suppressed[0].TargetID != "" || resolved.Run.Digest != document.Run.Digest {
		t.Fatal("normalizing evaluation changed caller ownership or run identity")
	}
	if resolved.Evaluation.Suppressed[1].TargetID != "" {
		t.Fatal("unrelated legacy approval acquired an invented target")
	}
	resolved.Evaluation.Suppressed[0].TargetID = "altered"
	if err := prepared.Snapshot().Validate(); err != nil {
		t.Fatal("snapshot mutation changed the prepared approval association")
	}
}

func TestSuppressionTargetAmbiguityFailsBeforeAnyOutput(t *testing.T) {
	document := documentFixture(t, false)
	document.Evaluation.Suppressed = document.Evaluation.Suppressed[:1]
	document.Run.Targets[1].Analysis.Findings[0].ID = document.Run.Targets[0].Analysis.Findings[0].ID
	run, err := report.SealRun(document.Run)
	if err != nil {
		t.Fatal(err)
	}
	document.Run, document.Evaluation.RunDigest = run, run.Digest
	if err := document.Validate(); err == nil || !strings.Contains(err.Error(), "unambiguous target") {
		t.Fatalf("ambiguous legacy approval was accepted: %v", err)
	}
	for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, document); err == nil || out.Len() != 0 {
			t.Fatal("ambiguous approval emitted a report")
		}
	}
	document.Evaluation.Suppressed[0].TargetID = run.Targets[0].ID
	if _, err := report.Prepare(document); err != nil {
		t.Fatalf("explicit target did not resolve the shared occurrence: %v", err)
	}
	for _, target := range []string{"missing-target", run.Targets[1].ID} {
		invalid := documentFixture(t, false)
		invalid.Evaluation.Suppressed[0].TargetID = target
		if _, err := report.Prepare(invalid); err == nil || !strings.Contains(err.Error(), "unknown target or finding") {
			t.Fatalf("mismatched scoped approval was accepted: %v", err)
		}
	}
}

func TestSingleLegacySuppressionResolvesItsTarget(t *testing.T) {
	document := documentFixture(t, false)
	document.Evaluation.Suppressed = document.Evaluation.Suppressed[:1]
	prepared, err := report.Prepare(document)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.Snapshot().Evaluation.Suppressed
	if len(resolved) != 1 || resolved[0].TargetID != document.Run.Targets[0].ID || document.Evaluation.Suppressed[0].TargetID != "" {
		t.Fatal("single legacy approval was left unscoped or mutated caller ownership")
	}
}
