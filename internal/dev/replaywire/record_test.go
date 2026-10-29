package replaywire_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/dev/replaywire"
	"github.com/skarm/scout/report"
)

func TestSavedReplayContract(t *testing.T) {
	valid := validRecord()
	if err := valid.Validate("fixture"); err != nil {
		t.Fatal(err)
	}
	for _, budget := range []int{1, 60} {
		r := valid
		r.BudgetSeconds = budget
		if err := r.Validate("fixture"); err != nil {
			t.Fatal("inclusive replay budget boundary rejected", budget, err)
		}
	}
	for _, state := range []report.State{report.RunIncomplete, report.RunFailed, report.RunCancelled} {
		r := valid
		r.State, r.Decision, r.Coverage = state, report.Review, report.Partial
		if err := r.Validate("fixture"); err != nil {
			t.Fatal(state, err)
		}
	}
	cases := map[string]func(*replaywire.Record){
		"version":          func(r *replaywire.Record) { r.Version = "other" },
		"empty_version":    func(r *replaywire.Record) { r.Version = "" },
		"budget_zero":      func(r *replaywire.Record) { r.BudgetSeconds = 0 },
		"budget_large":     func(r *replaywire.Record) { r.BudgetSeconds = 61 },
		"id":               func(r *replaywire.Record) { r.ID = "" },
		"id_case":          func(r *replaywire.Record) { r.ID = strings.Repeat("A", 64) },
		"id_hex":           func(r *replaywire.Record) { r.ID = strings.Repeat("x", 64) },
		"decision":         func(r *replaywire.Record) { r.Decision = "unknown" },
		"state":            func(r *replaywire.Record) { r.State = "unknown" },
		"unfinished_allow": func(r *replaywire.Record) { r.State = report.RunFailed },
		"complete_error":   func(r *replaywire.Record) { r.Error = "replay_deadline" },
		"complete_partial": func(r *replaywire.Record) { r.Coverage = report.Partial },
		"binding":          func(r *replaywire.Record) { r.RunDigest = "" },
		"binding_prefix":   func(r *replaywire.Record) { r.RunDigest = strings.Repeat("a", 64) },
		"binding_hex":      func(r *replaywire.Record) { r.RunDigest = "sha256:" + strings.Repeat("z", 64) },
		"fault":            func(r *replaywire.Record) { r.Diagnostics = []string{"analyzer_contract"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid
			change(&r)
			if err := r.Validate("fixture"); err == nil {
				t.Fatal("invalid saved replay accepted", r)
			}
		})
	}
}

func TestReplayAccountingIncludesRefusalsAndRuntimeErrors(t *testing.T) {
	var summary replaywire.Summary
	for _, state := range []report.State{report.RunComplete, report.RunIncomplete, report.RunFailed, report.RunCancelled} {
		r := validRecord()
		r.State = state
		summary.AddOutcome(r)
	}
	for _, code := range []string{"unsupported captured path", "input byte limit", "input file count limit", "replay_deadline"} {
		r := validRecord()
		r.Error = code
		summary.AddOutcome(r)
	}
	if summary != (replaywire.Summary{Complete: 1, Incomplete: 1, Failed: 6, RuntimeErrors: 3}) {
		t.Fatal(summary)
	}
}

func TestHistoricalComparisonHasExplicitVersionBoundary(t *testing.T) {
	r := validRecord()
	if err := replaywire.ValidateComparison(r); err != nil {
		t.Fatal(err)
	}
	r.Version, r.State, r.RunDigest, r.BudgetSeconds = "0.22.0-preview", "", "", 0
	if err := replaywire.ValidateComparison(r); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*replaywire.Record){
		func(r *replaywire.Record) { r.State = report.RunComplete },
		func(r *replaywire.Record) { r.ID = "invalid" },
		func(r *replaywire.Record) { r.Decision = "invalid" },
		func(r *replaywire.Record) { r.Coverage = report.Partial },
	} {
		bad := r
		change(&bad)
		if replaywire.ValidateComparison(bad) == nil {
			t.Fatal("invalid historical row accepted", bad)
		}
	}
	if r.Validate("0.22.0-preview") == nil {
		t.Fatal("historical comparison row accepted as current evidence")
	}
}

func TestCurrentRecordRequiresKnownCoverageForEveryState(t *testing.T) {
	for _, state := range []report.State{report.RunComplete, report.RunIncomplete, report.RunFailed, report.RunCancelled} {
		for _, coverage := range []report.Completeness{"", "not-a-coverage"} {
			r := validRecord()
			r.State, r.Decision, r.Coverage = state, report.Review, coverage
			if err := r.Validate("fixture"); err == nil {
				t.Fatalf("unknown coverage accepted for %s: %q", state, coverage)
			}
		}
	}
	for _, coverage := range []report.Completeness{report.Complete, report.Partial, report.Failed} {
		r := validRecord()
		r.State, r.Decision, r.Coverage = report.RunCancelled, report.Review, coverage
		if err := r.Validate("fixture"); err != nil {
			t.Fatalf("valid cancelled coverage %q rejected: %v", coverage, err)
		}
	}
}

func TestHistoricalComparisonRequiresKnownCoverage(t *testing.T) {
	for _, coverage := range []report.Completeness{"", "not-a-coverage", report.Complete, report.Partial, report.Failed} {
		r := validRecord()
		r.Version, r.State, r.RunDigest, r.BudgetSeconds = "0.22.0-preview", "", "", 0
		r.Decision, r.Coverage = report.Review, coverage
		err := replaywire.ValidateComparison(r)
		valid := coverage == report.Complete || coverage == report.Partial || coverage == report.Failed
		if (err == nil) != valid {
			t.Fatalf("historical coverage %q: %v", coverage, err)
		}
	}
}

func validRecord() replaywire.Record {
	return replaywire.Record{
		ID: strings.Repeat("a", 64), Version: "fixture", BudgetSeconds: 5,
		State: report.RunComplete, Coverage: report.Complete, Decision: report.Allow,
		RunDigest: "sha256:" + strings.Repeat("0", 64),
	}
}
