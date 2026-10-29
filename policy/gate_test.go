package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestGateThresholdMatrix(t *testing.T) {
	severities := []report.Severity{report.Info, report.Low, report.Medium, report.High, report.Critical}
	for _, threshold := range severities {
		for _, severity := range severities {
			t.Run(string(threshold)+"/"+string(severity), func(t *testing.T) {
				run := gateRun(t, severity)
				gate := newGate(t, policy.Options{FailAt: threshold})
				evaluation := gate.Evaluate(run, gateTime())
				want := report.Allow
				if severity.Rank() >= threshold.Rank() {
					want = report.Block
				}
				if evaluation.Decision != want || evaluation.RunDigest != run.Digest || !strings.HasPrefix(evaluation.PolicyDigest, "sha256:") {
					t.Fatalf("evaluation=%+v, want %s", evaluation, want)
				}
				code := 0
				if want != report.Allow {
					code = 1
				}
				if got := policy.Code(report.NewDocument(run, evaluation)); got != code {
					t.Fatalf("exit=%d, want %d", got, code)
				}
			})
		}
	}
}

func TestGateReviewBelowThresholdIsExplicit(t *testing.T) {
	run := gateRun(t, report.Medium)
	for _, requireReview := range []bool{false, true} {
		gate := newGate(t, policy.Options{FailAt: report.High, ReviewBelowThreshold: requireReview})
		got := gate.Evaluate(run, gateTime()).Decision
		want := report.Allow
		if requireReview {
			want = report.Review
		}
		if got != want {
			t.Fatalf("ReviewBelowThreshold=%v: got %s, want %s", requireReview, got, want)
		}
	}
}

func TestGateRejectsInvalidConfiguration(t *testing.T) {
	for _, options := range []policy.Options{
		{},
		{FailAt: "invented"},
		{ID: strings.Repeat("x", 129), FailAt: report.High},
		{FailAt: report.High, Approvals: &baseline.Document{}},
	} {
		if _, err := policy.New(options); err == nil {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
	run := gateRun(t, report.High)
	doc := gateApprovals(t, run, false)
	doc.Entries[0] = baseline.Entry{
		Kind:     "glob",
		RuleID:   "*",
		PathGlob: "*",
		Reason:   "explicit approval",
		Expires:  gateTime().Add(time.Hour).Format(time.RFC3339),
		Approved: true,
	}
	if _, err := policy.New(policy.Options{FailAt: report.High, Approvals: &doc}); err == nil {
		t.Fatal("glob approvals accepted without explicit permission")
	}
	if _, err := policy.New(policy.Options{FailAt: report.High, Approvals: &doc, AllowGlobs: true}); err != nil {
		t.Fatal(err)
	}
}

func TestGateCopiesApprovalsAndPreservesEvidence(t *testing.T) {
	run := gateRun(t, report.High)
	doc := gateApprovals(t, run, true)
	gate := newGate(t, policy.Options{FailAt: report.High, Approvals: &doc})
	before, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	doc.Entries[0].Approved = false
	doc.Entries[0].Fingerprint = strings.Repeat("f", 64)
	first := gate.Evaluate(run, gateTime())
	if first.Decision != report.Allow || len(first.Suppressed) != 1 || first.Suppressed[0].FindingID != "finding-1" {
		t.Fatalf("approval was aliased or ignored: %+v", first)
	}
	first.Suppressed[0].FindingID = "caller-mutated"
	first.Reasons[0] = "caller-mutated"
	second := gate.Evaluate(run, gateTime())
	if second.Decision != report.Allow || len(second.Suppressed) != 1 || second.Suppressed[0].FindingID != "finding-1" || second.Reasons[0] == "caller-mutated" {
		t.Fatalf("evaluation results share mutable data: %+v", second)
	}
	after, err := json.Marshal(run)
	if err != nil || string(after) != string(before) {
		t.Fatalf("gate changed raw run: %v", err)
	}
}

func TestGateExpiryIsExclusiveAndPendingRequiresReview(t *testing.T) {
	run := gateRun(t, report.High)
	doc := gateApprovals(t, run, true)
	gate := newGate(t, policy.Options{FailAt: report.High, Approvals: &doc})
	if got := gate.Evaluate(run, gateTime().Add(time.Hour-time.Nanosecond)); got.Decision != report.Allow {
		t.Fatalf("approval expired too soon: %+v", got)
	}
	if got := gate.Evaluate(run, gateTime().Add(time.Hour)); got.Decision != report.Block || len(got.Suppressed) != 0 {
		t.Fatalf("exclusive approval deadline ignored: %+v", got)
	}
	lowRun := gateRun(t, report.Low)
	pending := gateApprovals(t, lowRun, false)
	pendingGate := newGate(t, policy.Options{FailAt: report.High, Approvals: &pending})
	if got := pendingGate.Evaluate(lowRun, gateTime()); got.Decision != report.Review || len(got.Suppressed) != 0 {
		t.Fatalf("pending approval silently allowed: %+v", got)
	}
}

func TestGateSemanticProposalsRequireReview(t *testing.T) {
	run := gateRun(t, report.Low)
	run.Targets[0].Analysis.Semantic = report.SemanticReport{
		Enabled:      true,
		Completeness: report.Complete,
		Proposals: []report.SemanticProposal{{
			ID:                "proposal-1",
			SuggestedSeverity: report.Critical,
		}},
	}
	run = sealGateRun(t, run)
	got := newGate(t, policy.Options{FailAt: report.High}).Evaluate(run, gateTime())
	if got.Decision != report.Review {
		t.Fatalf("model suggestion was ignored or treated as static block: %+v", got)
	}
}

func TestSelectedScopeRequiresExplicitPolicy(t *testing.T) {
	run := gateRun(t, report.Low)
	run.Targets[0].Analysis.Diagnostics = []report.Diagnostic{{Code: "shell_semantics_limited", AffectsScope: false}}
	run = sealGateRun(t, run)
	if got := newGate(t, policy.Options{FailAt: report.High}).Evaluate(run, gateTime()); got.Decision != report.Review {
		t.Fatalf("implicit subset admission: %+v", got)
	}
	gate := newGate(t, policy.Options{FailAt: report.High, Scope: policy.SelectedScope})
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Allow {
		t.Fatalf("selected plan blocked despite completion: %+v", got)
	}
	run.Targets[0].Analysis.Diagnostics[0].AffectsScope = true
	run.State, run.Targets[0].State = report.RunIncomplete, report.RunIncomplete
	run = sealGateRun(t, run)
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Review || policy.Code(report.NewDocument(run, got)) != 2 {
		t.Fatalf("scope weakened execution gap: %+v", got)
	}
}

func TestGateIncompleteAndCorruptedRunsNeverAllow(t *testing.T) {
	for _, state := range []report.State{report.RunIncomplete, report.RunFailed, report.RunCancelled} {
		t.Run(string(state), func(t *testing.T) {
			for _, severity := range []report.Severity{report.Low, report.High} {
				run := gateRun(t, severity)
				run.State, run.Targets[0].State = state, state
				run.Targets[0].Analysis.Coverage.Completeness = report.Partial
				run = sealGateRun(t, run)
				evaluation := newGate(t, policy.Options{FailAt: report.High}).Evaluate(run, gateTime())
				want := report.Review
				if severity == report.High {
					want = report.Block
				}
				if evaluation.Decision != want || policy.Code(report.NewDocument(run, evaluation)) != 2 {
					t.Fatalf("incomplete evidence misclassified: %+v", evaluation)
				}
			}
		})
	}
	for _, change := range []func(*report.Run){
		func(r *report.Run) { r.Digest = "" },
		func(r *report.Run) { r.State = report.Unknown },
		func(r *report.Run) { r.Targets[0].State = report.Unknown },
		func(r *report.Run) { r.Targets[0].Analysis.Findings[0].Message = "altered" },
	} {
		run := gateRun(t, report.Low)
		change(&run)
		evaluation := newGate(t, policy.Options{FailAt: report.High}).Evaluate(run, gateTime())
		if evaluation.Decision != report.Review || policy.Code(report.NewDocument(run, evaluation)) != 2 {
			t.Fatalf("corrupted run allowed: %+v", evaluation)
		}
	}
}

func TestGateDefaultIdentityAndPolicyDigest(t *testing.T) {
	run := gateRun(t, report.Low)
	defaultGate := newGate(t, policy.Options{FailAt: report.High})
	explicit := newGate(t, policy.Options{ID: "strict-v1", FailAt: report.High})
	first, second := defaultGate.Evaluate(run, gateTime()), explicit.Evaluate(run, gateTime())
	if first.PolicyDigest == "" || !reflect.DeepEqual(first, second) {
		t.Fatalf("default policy identity is unstable: %+v %+v", first, second)
	}
	different := newGate(t, policy.Options{FailAt: report.Critical}).Evaluate(run, gateTime())
	if different.PolicyDigest == first.PolicyDigest {
		t.Fatal("different policies have the same digest")
	}
	for _, corrupt := range []func(*report.Document){
		func(d *report.Document) { d.Schema = "unknown" },
		func(d *report.Document) { d.Evaluation.RunDigest = "wrong" },
		func(d *report.Document) { d.Evaluation.PolicyDigest = "" },
		func(d *report.Document) { d.Evaluation.Decision = "unknown" },
	} {
		document := report.NewDocument(run, first)
		corrupt(&document)
		if policy.Code(document) != 2 {
			t.Fatalf("invalid document produced successful exit: %+v", document)
		}
	}
}

func TestGateCompareUsesCandidateAndReviewsChanges(t *testing.T) {
	run := gateRun(t, report.High)
	run.Operation = report.CompareOperation
	run.Targets[0].Role = "before"
	after := run.Targets[0]
	after.ID, after.Index, after.Role = "target-2", 1, "after"
	after.Analysis.Findings = nil
	run.Targets = append(run.Targets, after)
	run.Comparison = &report.UpdateDelta{Completeness: report.Complete, SameSnapshot: false}
	run = sealGateRun(t, run)
	gate := newGate(t, policy.Options{FailAt: report.High})
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Review || policy.Code(report.NewDocument(run, got)) != 1 {
		t.Fatalf("old finding blocked clean changed candidate: %+v", got)
	}
	run.Targets[1].Analysis.Findings = []report.Finding{{ID: "new", RuleID: "R1", Severity: report.High}}
	run = sealGateRun(t, run)
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Block || policy.Code(report.NewDocument(run, got)) != 1 {
		t.Fatalf("candidate high finding did not block: %+v", got)
	}
	run.Targets[0].Analysis.Findings = nil
	run.Targets[1].Analysis.Findings = nil
	run.Comparison.SameSnapshot = true
	run = sealGateRun(t, run)
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Allow || policy.Code(report.NewDocument(run, got)) != 0 {
		t.Fatalf("unchanged complete comparison did not allow: %+v", got)
	}
}

func TestGateCompareManifestSignalsUseOperatorThreshold(t *testing.T) {
	severities := []report.Severity{report.Info, report.Low, report.Medium, report.High, report.Critical}
	for _, threshold := range severities {
		for _, severity := range append(severities, report.Severity("unknown")) {
			t.Run(string(threshold)+"/"+string(severity), func(t *testing.T) {
				run := gateRun(t, report.Low)
				run.Targets[0].Analysis.Findings = nil
				run.Operation = report.CompareOperation
				run.Targets[0].Role = "before"
				after := run.Targets[0]
				after.ID, after.Index, after.Role = "after", 1, "after"
				run.Targets = append(run.Targets, after)
				run.Comparison = &report.UpdateDelta{
					Completeness: report.Complete,
					SameSnapshot: true,
					ManifestSignals: []report.ManifestSignal{{
						RuleID:   "NV-RP1",
						Severity: severity,
					}},
				}
				run = sealGateRun(t, run)
				got := newGate(t, policy.Options{FailAt: threshold}).Evaluate(run, gateTime())
				want := report.Review
				if severity.Rank() >= threshold.Rank() {
					want = report.Block
				}
				if got.Decision != want {
					t.Fatalf("decision=%s want=%s", got.Decision, want)
				}
				if slices.Contains(got.Reasons, "invalid_manifest_signal_severity") != (severity.Rank() < 0) {
					t.Fatalf("severity classification: %+v", got)
				}
			})
		}
	}
}

func TestGateComparePreservesPreviousProposalReview(t *testing.T) {
	run := gateRun(t, report.Low)
	run.Operation = report.CompareOperation
	run.Targets[0].Role = "before"
	after := run.Targets[0]
	after.ID, after.Index, after.Role = "after", 1, "after"
	run.Targets = append(run.Targets, after)
	run.Targets[0].Analysis.Semantic = report.SemanticReport{
		Enabled:      true,
		Completeness: report.Complete,
		Proposals:    []report.SemanticProposal{{ID: "previous"}},
	}
	run.Comparison = &report.UpdateDelta{Completeness: report.Complete, SameSnapshot: true}
	run = sealGateRun(t, run)
	if got := newGate(t, policy.Options{FailAt: report.High}).Evaluate(run, gateTime()); got.Decision != report.Review {
		t.Fatalf("previous review obligation lost: %+v", got)
	}
}

func TestGateZeroValueAndInvalidRawSeverityCannotAllow(t *testing.T) {
	run := gateRun(t, report.Low)
	var zero policy.Gate
	var missing *policy.Gate
	for _, gate := range []*policy.Gate{&zero, missing} {
		evaluation := gate.Evaluate(run, gateTime())
		if evaluation.Decision != report.Review || policy.Code(report.NewDocument(run, evaluation)) != 2 {
			t.Fatalf("invalid gate allowed admission: %+v", evaluation)
		}
	}
	run.Targets[0].Analysis.Findings[0].Severity = "unknown"
	run = sealGateRun(t, run)
	approvals := gateApprovals(t, run, true)
	gate := newGate(t, policy.Options{FailAt: report.High, Approvals: &approvals})
	if got := gate.Evaluate(run, gateTime()); got.Decision != report.Review {
		t.Fatalf("approval sanitized an invalid raw finding: %+v", got)
	}
}

func TestGateAggregatesTargetsAndDocumentRoundTrip(t *testing.T) {
	run := gateRun(t, report.High)
	approvals := gateApprovals(t, run, true)
	second := run.Targets[0]
	second.ID, second.Index = "target-2", 1
	second.Analysis.Findings = []report.Finding{{ID: "finding-2", RuleID: "R2", Severity: report.Low}}
	run.Targets = append(run.Targets, second)
	run = sealGateRun(t, run)
	gate := newGate(t, policy.Options{FailAt: report.High, Approvals: &approvals})
	evaluation := gate.Evaluate(run, gateTime())
	if evaluation.Decision != report.Allow || len(evaluation.Suppressed) != 1 || evaluation.Suppressed[0].FindingID != "finding-1" {
		t.Fatalf("incorrect multi-target evaluation: %+v", evaluation)
	}
	data, err := json.Marshal(report.NewDocument(run, evaluation))
	if err != nil {
		t.Fatal(err)
	}
	var document report.Document
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if code := policy.Code(document); code != 0 {
		t.Fatalf("JSON round trip changed successful exit: %d", code)
	}
}

func TestPolicyDefaultsPreserveWireIdentityAndCallerOptions(t *testing.T) {
	options := policy.Options{FailAt: report.Info}
	gate := newGate(t, options)
	got := gate.Evaluate(gateRun(t, report.Info), gateTime())
	identity := `{"version":"gate-v1","options":{"id":"strict-v1","fail_at":"info","allow_globs":false,"review_below_threshold":false,"scope":"conservative"}}`
	digest := sha256.Sum256([]byte(identity))
	if got.PolicyDigest != "sha256:"+hex.EncodeToString(digest[:]) || got.Decision != report.Block {
		t.Fatalf("default policy identity changed: %+v", got)
	}
	if options.ID != "" || options.Scope != "" {
		t.Fatal("normalization changed caller options")
	}
}

func TestPolicyRejectsInvalidSettingsBeforeApprovals(t *testing.T) {
	for _, tc := range []struct {
		options policy.Options
		want    string
	}{
		{
			options: policy.Options{Scope: "unknown", FailAt: "unknown", Approvals: &baseline.Document{}},
			want:    "invalid scope policy",
		},
		{
			options: policy.Options{ID: strings.Repeat("é", 65), FailAt: report.High, Approvals: &baseline.Document{}},
			want:    "invalid policy ID or blocking threshold",
		},
		{
			options: policy.Options{ID: "accepted", FailAt: "unknown", Approvals: &baseline.Document{}},
			want:    "invalid policy ID or blocking threshold",
		},
	} {
		if _, err := policy.New(tc.options); err == nil || err.Error() != tc.want {
			t.Fatalf("got %v, want %s", err, tc.want)
		}
	}
}

func TestPolicyIDLimitCountsBytes(t *testing.T) {
	for _, id := range []string{strings.Repeat("x", 128), strings.Repeat("é", 64)} {
		if _, err := policy.New(policy.Options{ID: id, FailAt: report.Info}); err != nil {
			t.Fatalf("128-byte policy ID rejected: %v", err)
		}
	}
	if _, err := policy.New(policy.Options{ID: strings.Repeat("x", 129), FailAt: report.Info}); err == nil {
		t.Fatal("129-byte policy ID accepted")
	}
}

func newGate(t *testing.T, options policy.Options) *policy.Gate {
	t.Helper()
	gate, err := policy.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func gateRun(t *testing.T, severity report.Severity) report.Run {
	t.Helper()
	analysis := report.Analysis{
		EngineVersion:  "fixture",
		RulepackDigest: "sha256:" + strings.Repeat("c", 64),
		Profile:        "fixture",
		Coverage:       report.Coverage{Completeness: report.Complete},
		Findings: []report.Finding{{
			ID:       "finding-1",
			RuleID:   "R1",
			Severity: severity,
			Message:  "observed",
			Location: report.Location{Path: "input.txt"},
		}},
	}
	return sealGateRun(t, report.Run{
		State:     report.RunComplete,
		Operation: report.ScanOperation,
		Targets: []report.TargetResult{{
			ID:       "target-1",
			Index:    0,
			State:    report.RunComplete,
			Analysis: analysis,
		}},
	})
}

func sealGateRun(t *testing.T, run report.Run) report.Run {
	t.Helper()
	sealed, err := report.SealRun(run)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func gateApprovals(t *testing.T, run report.Run, approved bool) baseline.Document {
	t.Helper()
	document, err := baseline.Create(run.Targets[0].Analysis, "reviewed fixture", gateTime().Add(time.Hour), approved)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func gateTime() time.Time { return time.Date(2026, time.October, 27, 0, 0, 0, 0, time.UTC) }
