package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/engine"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestFailuresNeverAllow(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(context.Context, document.File, int) (analyzer.Result, error)
	}{
		{name: "error", fn: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{}, errors.New("SECRET_SENTINEL")
		}},
		{
			name: "panic",
			fn:   func(context.Context, document.File, int) (analyzer.Result, error) { panic("SECRET_SENTINEL") },
		},
		{name: "bad-span", fn: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 99}}}, nil
		}},
		{name: "budget", fn: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1}, {Start: 0, End: 1}}}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := engine.New([]analyzer.Analyzer{fake{id: "FAIL", find: tc.fn}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			l := report.DefaultCaptureLimits()
			l.MaxFindings = 1
			r, err := e.Run(context.Background(), fixture(), options(l))
			if err != nil {
				t.Fatal(err)
			}
			if r.Coverage.Completeness != "partial" || decision(r) == "allow" || r.Coverage.Checks[0].Status != "failed" {
				t.Fatalf("failed analyzer allowed: %+v", r)
			}
			for _, d := range r.Diagnostics {
				if d.Message == "SECRET_SENTINEL" {
					t.Fatal("exception leaked")
				}
			}
		})
	}
}

func TestFailurePreservesOtherFindings(t *testing.T) {
	e, err := engine.New([]analyzer.Analyzer{
		fake{id: "GOOD", find: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1}}}, nil
		}},
		fake{id: "BAD", find: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{}, errors.New("failed")
		}},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Run(context.Background(), fixture(), options(report.DefaultCaptureLimits()))
	if err != nil || len(r.Findings) != 1 || decision(r) != "block" || r.Coverage.Completeness != "partial" {
		t.Fatal("failure discarded evidence")
	}
}

func TestEngineRejectsInvalidConfig(t *testing.T) {
	good := fake{
		id:   "A",
		find: func(context.Context, document.File, int) (analyzer.Result, error) { return analyzer.Result{}, nil },
	}
	for _, tc := range []struct {
		name    string
		checks  []analyzer.Analyzer
		workers int
	}{{name: "none", checks: nil, workers: 1}, {name: "nil", checks: []analyzer.Analyzer{nil}, workers: 1}, {
		name:    "duplicate",
		checks:  []analyzer.Analyzer{good, good},
		workers: 1,
	}, {
		name:    "workers",
		checks:  []analyzer.Analyzer{good},
		workers: 0,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := engine.New(tc.checks, tc.workers); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestPartialResultOnErrorIsPreserved(t *testing.T) {
	e, err := engine.New([]analyzer.Analyzer{fake{
		id: "PARTIAL",
		find: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1}}}, errors.New("SECRET_SENTINEL")
		},
	}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Run(context.Background(), fixture(), options(report.DefaultCaptureLimits()))
	if err != nil || len(r.Findings) != 1 || decision(r) != "block" || r.Coverage.Completeness != "partial" || r.Coverage.Checks[0].FilesDone != 0 {
		t.Fatalf("partial evidence lost: %+v %v", r, err)
	}
}

func TestInvalidTraceRejected(t *testing.T) {
	for _, trace := range [][]analyzer.Trace{
		{{Role: "SECRET_SENTINEL", Start: 0, End: 1}},
		{{Role: "source", Start: 0, End: 99}},
		make([]analyzer.Trace, 9),
	} {
		e, err := engine.New([]analyzer.Analyzer{fake{
			id: "TRACE",
			find: func(context.Context, document.File, int) (analyzer.Result, error) {
				return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1, Trace: trace}}}, nil
			},
		}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.Run(context.Background(), fixture(), options(report.DefaultCaptureLimits()))
		if err != nil || len(r.Findings) != 0 || r.Coverage.Completeness != "partial" {
			t.Fatal("invalid trace accepted")
		}
	}
}

func TestFindingSeverityCannotExceedRuleMaximum(t *testing.T) {
	for _, tc := range []struct {
		severity report.Severity
		valid    bool
		decision report.Decision
	}{
		{severity: report.Low, valid: true, decision: report.Review}, {
			severity: "",
			valid:    true,
			decision: report.Block,
		}, {
			severity: report.Critical,
			valid:    false,
			decision: report.Review,
		}, {
			severity: report.Severity("unknown"),
			valid:    false,
			decision: report.Review,
		},
	} {
		t.Run(string(tc.severity), func(t *testing.T) {
			a := fake{id: "SEVERITY", find: func(context.Context, document.File, int) (analyzer.Result, error) {
				return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1, Severity: tc.severity}}}, nil
			}}
			e, err := engine.New([]analyzer.Analyzer{a}, 1)
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.Run(context.Background(), fixture(), options(report.DefaultCaptureLimits()))
			if err != nil {
				t.Fatal(err)
			}
			if tc.valid {
				if len(r.Findings) != 1 || decision(r) != tc.decision {
					t.Fatalf("valid severity: %+v", r)
				}
			} else if len(r.Findings) != 0 || r.Coverage.Completeness != report.Partial || decision(r) == report.Allow {
				t.Fatalf("invalid severity accepted: %+v", r)
			}
		})
	}
}

func TestAnalyzerContextLabelsAreBoundedAndScannerOwned(t *testing.T) {
	for _, signals := range [][]string{{"SENTINEL_UNTRUSTED_LABEL"}, {"registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion", "registry_assertion"}} {
		a := fake{id: "CONTEXT", find: func(context.Context, document.File, int) (analyzer.Result, error) {
			return analyzer.Result{Matches: []analyzer.Match{{Start: 0, End: 1, ContextSignals: signals}}}, nil
		}}
		e, err := engine.New([]analyzer.Analyzer{a}, 1)
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.Run(context.Background(), fixture(), options(report.DefaultCaptureLimits()))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Findings) != 0 || r.Coverage.Completeness != report.Partial || decision(r) == report.Allow {
			t.Fatalf("unvalidated context accepted: %+v", r)
		}
	}
}

func TestIncompleteCaptureWithoutDiagnosticNeverCompletes(t *testing.T) {
	e, err := engine.New([]analyzer.Analyzer{fake{
		id:   "OK",
		find: func(context.Context, document.File, int) (analyzer.Result, error) { return analyzer.Result{}, nil },
	}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := artifact.New("directory", []artifact.File{artifact.NewFile("SKILL.md", []byte("ordinary prose"), false)}, nil, nil, false)
	result, err := e.Run(context.Background(), snapshot, options(report.DefaultCaptureLimits()))
	if err != nil || result.Coverage.Completeness != report.Partial || result.Artifact.InventoryComplete {
		t.Fatalf("incomplete capture incorrectly completed: %+v,%v", result.Coverage, err)
	}
}

type fake struct {
	id   string
	find func(context.Context, document.File, int) (analyzer.Result, error)
}

func (a fake) Rule() report.Rule {
	return report.Rule{ID: a.id, Version: "1", Severity: report.High, Title: "test", Method: "test"}
}
func (a fake) AppliesTo(document.File) bool { return true }
func (a fake) Find(ctx context.Context, f document.File, n int) (analyzer.Result, error) {
	return a.find(ctx, f, n)
}

func options(limits report.CaptureLimits) engine.RunOptions {
	return engine.RunOptions{
		Engine: report.EngineIdentity{Version: "fixture", RulepackDigest: "sha256:fixture"}, Profile: "custom",
		Limits: limits, Extraction: report.DefaultExtractionLimits(),
		Harness: report.HarnessOptions{Host: "auto"}, Semantic: review.DefaultOptions(),
		Vulnerabilities: osv.DefaultOptions(),
	}
}

func fixture() artifact.Snapshot {
	return artifact.New("directory", []artifact.File{artifact.NewFile("SKILL.md", []byte("x"), false)}, nil, nil, true)
}

func decision(r report.Analysis) report.Decision {
	state := report.RunComplete
	if r.Coverage.Completeness != report.Complete {
		state = report.RunIncomplete
	}
	run, err := report.SealRun(report.Run{
		Operation: report.ScanOperation,
		State:     state,
		Targets: []report.TargetResult{{
			ID:       "fixture",
			Index:    0,
			State:    state,
			Analysis: r,
		}},
	})
	if err != nil {
		panic(err)
	}
	gate, err := policy.New(policy.Options{ID: "test", FailAt: report.High, ReviewBelowThreshold: true})
	if err != nil {
		panic(err)
	}
	return gate.Evaluate(run, time.Unix(0, 0).UTC()).Decision
}
