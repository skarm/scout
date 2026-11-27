package policy_test

import (
	"testing"

	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestPolicyComparisonReportsObservationChangesDespiteUnchangedDecision(t *testing.T) {
	run := gateRun(t, report.Medium)
	run.Operation = report.CompareOperation
	run.Targets[0].Role = "before"
	after := run.Targets[0]
	after.ID, after.Index, after.Role = "after", 1, "after"
	run.Targets = append(run.Targets, after)
	run.Comparison = &report.UpdateDelta{
		Completeness: report.Complete,
		ManifestSignals: []report.ManifestSignal{
			{RuleID: "manifest-critical", Severity: report.Critical},
			{RuleID: "manifest-medium", Severity: report.Medium},
		},
	}
	run = sealGateRun(t, run)
	current := newGate(t, policy.Options{FailAt: report.Medium})
	trial := newGate(t, policy.Options{FailAt: report.High, ReviewBelowThreshold: true})
	got, err := policy.Compare(run, current, trial, gateTime())
	if err != nil {
		t.Fatal(err)
	}
	if got.DecisionChanged || got.Current.Decision != report.Block || got.Trial.Decision != report.Block {
		t.Fatalf("critical signal should preserve blocking decision: %+v", got)
	}
	if len(got.FindingChanges) != 1 || got.FindingChanges[0].TargetID != after.ID ||
		got.FindingChanges[0].Current != policy.DispositionBlock || got.FindingChanges[0].Trial != policy.DispositionReview {
		t.Fatalf("expected one candidate occurrence to change disposition: %+v", got.FindingChanges)
	}
	if len(got.ManifestSignalChanges) != 1 || got.ManifestSignalChanges[0].RuleID != "manifest-medium" ||
		got.ManifestSignalChanges[0].Current != policy.DispositionBlock || got.ManifestSignalChanges[0].Trial != policy.DispositionReview {
		t.Fatalf("manifest threshold delta missing: %+v", got.ManifestSignalChanges)
	}
}
