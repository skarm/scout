//nolint:testpackage // Exercises private implementation details and package fixtures.
package provenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestReplayEvidenceRejectsFalseCompletionAndMutation(t *testing.T) {
	root := t.TempDir()
	row := replayRow{
		ID:            "0000000000000000000000000000000000000000000000000000000000000001",
		Version:       "fixture",
		BudgetSeconds: 5,
		State:         report.RunComplete,
		Coverage:      report.Complete,
		Decision:      report.Allow,
		RunDigest:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	write := func(row replayRow) artifact {
		t.Helper()
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "replay.jsonl")
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		artifact, err := artifactIdentity(context.Background(), root, path)
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	artifact := write(row)
	got, err := readReplay(context.Background(), root, artifact, "fixture")
	if err != nil || got.summary.Inputs != 1 || got.summary.Complete != 1 {
		t.Fatal(got.summary, err)
	}
	for _, change := range []func(*replayRow){
		func(r *replayRow) { r.State = report.RunIncomplete },
		func(r *replayRow) { r.RunDigest = "" },
		func(r *replayRow) { r.Diagnostics = []string{"analyzer_panic"} },
		func(r *replayRow) { r.Error = "replay_deadline" },
	} {
		broken := row
		change(&broken)
		if _, err := readReplay(context.Background(), root, write(broken), "fixture"); err == nil {
			t.Fatal("invalid replay accepted", broken)
		}
	}
	write(row)
	if err := os.WriteFile(filepath.Join(root, "replay.jsonl"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReplay(context.Background(), root, artifact, "fixture"); err == nil {
		t.Fatal("changed artifact accepted")
	}
}

func TestComparisonCannotHideChangedObservations(t *testing.T) {
	id := "input"
	before := replayEvidence{
		ids: []string{id},
		rows: map[string]observedRow{id: {observations: []Observation{{
			RuleID: "R",
			Path:   "x",
			Start:  1,
			End:    2,
		}}}},
	}
	after := replayEvidence{
		ids: []string{id},
		rows: map[string]observedRow{id: {observations: []Observation{{
			RuleID: "R",
			Path:   "x",
			Start:  2,
			End:    3,
		}}}},
	}
	delta, err := compareEvidence(before, after)
	if err != nil || delta.ChangedRows != 1 || len(delta.Changes[0].Added) != 1 || len(delta.Changes[0].Removed) != 1 {
		t.Fatal(delta, err)
	}
	if verifyAdjudication(t.TempDir(), delta.Changes[0]) == nil {
		t.Fatal("unadjudicated change accepted")
	}
	after.rows[id] = observedRow{error: true}
	delta, err = compareEvidence(before, after)
	if err != nil || delta.ChangedRows != 0 || delta.ExcludedExecutionErrorRows != 1 {
		t.Fatal("runtime fault counted as equivalence", delta, err)
	}
}

func TestInputVerificationRequiresTrustedPins(t *testing.T) {
	manifest := Manifest{
		Input: artifact{
			Path:   "capture.gz",
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		InputIDsSHA256: idsDigest([]string{"input"}),
	}
	if err := verifyInput(context.Background(), t.TempDir(), manifest, Verification{InputMode: inputPinned}, []string{"input"}); err == nil {
		t.Fatal("missing trusted pins accepted")
	}
	options := Verification{
		InputMode: inputPinned,
		InputPin: file{
			Path:   manifest.Input.Path,
			SHA256: manifest.Input.SHA256,
		},
		IDsSHA256: manifest.InputIDsSHA256,
	}
	if err := verifyInput(context.Background(), t.TempDir(), manifest, options, []string{"input"}); err != nil {
		t.Fatal(err)
	}
	if err := verifyInput(context.Background(), t.TempDir(), manifest, options, []string{"another"}); err == nil {
		t.Fatal("replacement input set accepted")
	}
}

func TestChangedReplayRequiresBoundAdjudicationAndExistingRegression(t *testing.T) {
	root := t.TempDir()
	write := func(path string, value any) artifact {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		identity, err := artifactIdentity(t.Context(), root, path)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	row := replayRow{
		ID:            strings.Repeat("a", 64),
		Version:       "fixture",
		BudgetSeconds: 5,
		State:         report.RunComplete,
		Coverage:      report.Complete,
		Decision:      report.Review,
		RunDigest:     "sha256:" + strings.Repeat("b", 64),
		Findings:      []report.Finding{},
		Diagnostics:   []string{},
	}
	write("before.jsonl", row)
	row.Findings = []report.Finding{{RuleID: "R", Location: report.Location{Path: "x", ByteStart: 1, ByteEnd: 2}}}
	after := write("after.jsonl", row)
	comparison, err := Compare(t.Context(), root, "before.jsonl", "after.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if comparison.ChangedRows != 1 || len(comparison.Changes[0].Added) != 1 {
		t.Fatal(comparison)
	}
	observed, err := readReplay(t.Context(), root, after, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	after.UncompressedSHA256 = observed.contentSHA256
	if verifyComparisonArtifact(t.Context(), root, write("comparison.json", comparison), after, observed) == nil {
		t.Fatal("unadjudicated change accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "evidence_test.go"), []byte("package fixture\nfunc TestFixedRegression() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	comparison.Changes[0].Adjudication = &adjudication{
		Reason: "fixed fixture regression",
		Test:   "evidence_test.go:TestFixedRegression",
	}
	if err := verifyComparisonArtifact(t.Context(), root, write("comparison.json", comparison), after, observed); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{"wrong", "../outside_test.go:TestFixedRegression", "evidence_test.go:not_a_test", "missing_test.go:TestFixedRegression", "evidence_test.go:TestMissing"} {
		change := comparison.Changes[0]
		change.Adjudication = &adjudication{Reason: "fixture", Test: reference}
		if verifyAdjudication(root, change) == nil {
			t.Fatal("unbound regression accepted", reference)
		}
	}
	bad := comparison
	bad.After.SHA256 = strings.Repeat("0", 64)
	if verifyComparisonArtifact(context.Background(), root, write("comparison.json", bad), after, observed) == nil {
		t.Fatal("changed current binding accepted")
	}
}
