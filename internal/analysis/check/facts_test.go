package check_test

import (
	"errors"
	"testing"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/report"
)

func TestFactsPreserveTerminalAndConsumerBudgetOrdering(t *testing.T) {
	failure := errors.New("walker failed")
	for _, tc := range []struct {
		name                        string
		collection, consumer, count int
		limited                     bool
		err                         error
		wantCount                   int
		wantLimited                 bool
		wantError                   error
	}{
		{
			name:        "complete-at-exact-budget",
			collection:  1,
			consumer:    1,
			count:       1,
			limited:     false,
			err:         nil,
			wantCount:   1,
			wantLimited: false,
			wantError:   nil,
		},
		{
			name:        "complete-empty-zero-budget",
			collection:  0,
			consumer:    0,
			count:       0,
			limited:     false,
			err:         nil,
			wantCount:   0,
			wantLimited: false,
			wantError:   nil,
		},
		{
			name:        "smaller-consumer-before-later-error",
			collection:  8,
			consumer:    1,
			count:       1,
			limited:     false,
			err:         failure,
			wantCount:   1,
			wantLimited: true,
			wantError:   nil,
		},
		{
			name:        "full-consumer-retains-prefix-and-error",
			collection:  8,
			consumer:    2,
			count:       1,
			limited:     false,
			err:         failure,
			wantCount:   1,
			wantLimited: false,
			wantError:   failure,
		},
		{
			name:        "error-precedes-simultaneous-limit",
			collection:  8,
			consumer:    2,
			count:       1,
			limited:     true,
			err:         failure,
			wantCount:   1,
			wantLimited: false,
			wantError:   failure,
		},
		{
			name:        "collection-limit-precedes-later-error",
			collection:  1,
			consumer:    8,
			count:       2,
			limited:     false,
			err:         failure,
			wantCount:   1,
			wantLimited: true,
			wantError:   nil,
		},
		{
			name:        "semantic-limit-retains-prefix",
			collection:  8,
			consumer:    8,
			count:       1,
			limited:     true,
			err:         nil,
			wantCount:   1,
			wantLimited: true,
			wantError:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := check.NewFacts(tc.collection)
			for i := range tc.count {
				facts.Add(check.Match{Start: i, End: i + 1})
			}
			facts.Finish(tc.err, tc.limited)
			facts.Finish(errors.New("later failure"), true)
			facts.Add(check.Match{Start: 99, End: 100})
			out, err := facts.Result(tc.consumer)
			if !errors.Is(err, tc.wantError) || len(out.Matches) != tc.wantCount || out.Truncated != tc.wantLimited || facts.MatchCount() != tc.wantCount || !facts.Done() {
				t.Fatalf("result=%+v error=%v count=%d done=%v", out, err, facts.MatchCount(), facts.Done())
			}
		})
	}
}

func TestFactsAdmissionPrecedesCandidatePreparation(t *testing.T) {
	facts := check.NewFacts(1)
	if !facts.Admit() {
		t.Fatal("first candidate refused")
	}
	facts.Add(check.Match{Start: 1, End: 2})
	if facts.Admit() {
		t.Fatal("candidate beyond collection budget reached preparation")
	}
	facts.Finish(errors.New("mapping failed"), false)
	out, err := facts.Result(8)
	if err != nil || len(out.Matches) != 1 || !out.Truncated {
		t.Fatalf("later mapping failure replaced earlier cap: %+v %v", out, err)
	}
}

func TestFactsMissingStreamsAllowTheWholeConsumerLifecycle(t *testing.T) {
	var absent *check.Facts
	selected := map[string]*check.Facts{}
	for name, facts := range map[string]*check.Facts{"unset": absent, "unselected-rule": selected["missing"]} {
		t.Run(name, func(t *testing.T) {
			if facts.Admit() {
				t.Fatal("missing stream admitted a candidate")
			}
			facts.Add(check.Match{Start: 1, End: 2})
			facts.Finish(errors.New("unused stream failure"), true)
			facts.Finish(nil, false)
			out, err := facts.Result(0)
			if err != nil || len(out.Matches) != 0 || out.Truncated || !facts.Done() || facts.MatchCount() != 0 {
				t.Fatalf("missing stream did not remain complete and empty: result=%+v error=%v count=%d done=%v", out, err, facts.MatchCount(), facts.Done())
			}
		})
	}
}

func TestFactsConsumersOwnMutableEvidence(t *testing.T) {
	t.Parallel()
	facts := check.NewFacts(8)
	facts.Add(check.Match{
		Start:          1,
		End:            2,
		Trace:          []check.Trace{{Start: 3, End: 4}},
		Related:        []report.SourceRef{{Path: "source"}},
		ContextSignals: []string{"declared"},
	})
	facts.Finish(nil, false)
	for range 8 {
		t.Run("consumer", func(t *testing.T) {
			t.Parallel()
			first, err := facts.Result(8)
			if err != nil || len(first.Matches) != 1 {
				t.Fatal(first, err)
			}
			first.Matches[0].Trace[0].Start = 99
			first.Matches[0].Related[0].Path = "mutated"
			first.Matches[0].ContextSignals[0] = "mutated"
			second, err := facts.Result(8)
			if err != nil || second.Matches[0].Trace[0].Start != 3 || second.Matches[0].Related[0].Path != "source" || second.Matches[0].ContextSignals[0] != "declared" {
				t.Fatal("consumer mutated immutable facts", second, err)
			}
		})
	}
}
