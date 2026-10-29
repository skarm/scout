package python //nolint:testpackage // Tests exercise private fact storage and bounded evidence projection.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestPythonFactsBudgetPrecedesLaterMappingError(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"AST1"}, 8)
	facts.emit("AST1", &frontend.Node{Start: 0, End: 1}, nil, unit)
	facts.emit("AST1", &frontend.Node{Start: 8, End: 12}, nil, unit)
	facts.finish(nil, false)
	limited, err := facts.result("AST1", 1)
	if err != nil || len(limited.Matches) != 1 || !limited.Truncated {
		t.Fatalf("smaller budget inherited later error: %+v %v", limited, err)
	}
	full, err := facts.result("AST1", 8)
	if err == nil || err.Error() != "python source mapping failed" || len(full.Matches) != 1 || full.Truncated {
		t.Fatalf("source mapping failure lost: %+v %v", full, err)
	}
}

func TestPythonFactsCollectionCapPrecedesMapping(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"AST1"}, 1)
	facts.emit("AST1", &frontend.Node{Start: 0, End: 1}, nil, unit)
	facts.emit("AST1", &frontend.Node{Start: 8, End: 12}, nil, unit)
	if !facts.exhausted() {
		t.Fatal("capped rule was not finished")
	}
	out, err := facts.result("AST1", 8)
	if err != nil || len(out.Matches) != 1 || !out.Truncated {
		t.Fatalf("collection cap inherited mapping error: %+v %v", out, err)
	}
}

func TestPythonFactsPerRuleIsolationAndFinishPriority(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"AST1", "AST2"}, 8)
	facts.emit("unselected", &frontend.Node{Start: 99, End: 100}, nil, unit)
	facts.emit("AST1", &frontend.Node{Start: 99, End: 100}, nil, unit)
	if facts.exhausted() {
		t.Fatal("one rule's failure exhausted another rule")
	}
	facts.emit("AST2", &frontend.Node{Start: 1, End: 2}, nil, unit)
	terminal := errors.New("terminal failure")
	facts.finish(terminal, true)
	first, err := facts.result("AST1", 8)
	if err == nil || err.Error() != "python source mapping failed" || len(first.Matches) != 0 || first.Truncated {
		t.Fatalf("finished rule was overwritten: %+v %v", first, err)
	}
	second, err := facts.result("AST2", 8)
	if !errors.Is(err, terminal) || len(second.Matches) != 1 || second.Truncated {
		t.Fatalf("error did not take precedence over limit: %+v %v", second, err)
	}
	if !facts.exhausted() {
		t.Fatal("finish did not close all selected rules")
	}
}

func TestPythonFactsDedupResetsForEveryUnit(t *testing.T) {
	first := pythonFactsUnit(t, "01234567890123456789", source.Span{Start: 0, End: 10})
	second := pythonFactsUnit(t, "01234567890123456789", source.Span{Start: 10, End: 20})
	facts := newPythonFacts([]string{"AST1", "AST2"}, 8)
	node := &frontend.Node{Start: 1, End: 3}
	facts.emit("AST1", node, nil, first)
	facts.emit("AST1", node, nil, first)
	facts.emit("AST2", node, nil, first)
	facts.beginUnit()
	facts.emit("AST1", node, nil, second)
	facts.finish(nil, false)
	out, err := facts.result("AST1", 8)
	if err != nil || !reflect.DeepEqual(out.Matches, []match{{Start: 1, End: 3}, {Start: 11, End: 13}}) || out.Truncated {
		t.Fatalf("wrong per-unit candidate order: %+v %v", out, err)
	}
	other, err := facts.result("AST2", 8)
	if err != nil || len(other.Matches) != 1 {
		t.Fatalf("per-rule dedup leaked across rules: %+v %v", other, err)
	}
}

func TestPythonFactsCopiesMappedTraceResults(t *testing.T) {
	unit := pythonFactsUnit(t, "prefix0123456789tail", source.Span{Start: 6, End: 16})
	facts := newPythonFacts([]string{"TT1"}, 8)
	origin := &pyOrigin{start: 0, end: 1, steps: []source.Span{{Start: 2, End: 4}}}
	facts.emit("TT1", &frontend.Node{Start: 6, End: 8}, origin, unit)
	facts.finish(nil, false)
	first, err := facts.result("TT1", 8)
	want := match{
		Start: 12,
		End:   14,
		Trace: []trace{{Role: "source", Start: 6, End: 7}, {
			Role:  "transform",
			Start: 8,
			End:   10,
		}, {
			Role:  "sink",
			Start: 12,
			End:   14,
		}},
	}
	if err != nil || len(first.Matches) != 1 || !reflect.DeepEqual(first.Matches[0], want) {
		t.Fatalf("incorrect mapped evidence: %+v %v", first, err)
	}
	origin.steps[0] = source.Span{Start: 7, End: 9}
	first.Matches[0].Start = 99
	first.Matches[0].Trace[0].Start = 99
	second, err := facts.result("TT1", 8)
	if err != nil || !reflect.DeepEqual(second.Matches[0], want) {
		t.Fatalf("result or input aliased facts: %+v %v", second, err)
	}
}

func TestPythonFactsTraceFailureIsLocal(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"TT1", "AST1"}, 8)
	facts.emit("TT1", &frontend.Node{Start: 1, End: 2}, &pyOrigin{start: 7, end: 20}, unit)
	facts.emit("AST1", &frontend.Node{Start: 1, End: 2}, nil, unit)
	facts.finish(nil, false)
	out, err := facts.result("TT1", 8)
	if err == nil || err.Error() != "python trace mapping failed" || len(out.Matches) != 0 {
		t.Fatalf("partial trace was accepted: %+v %v", out, err)
	}
	other, err := facts.result("AST1", 8)
	if err != nil || len(other.Matches) != 1 {
		t.Fatalf("trace error contaminated other rule: %+v %v", other, err)
	}
}

func TestPythonFactsSemanticLimitAndExactBudget(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	for _, truncated := range []bool{false, true} {
		facts := newPythonFacts([]string{"AST1"}, 1)
		facts.emit("AST1", &frontend.Node{Start: 0, End: 1}, nil, unit)
		facts.emit("AST1", &frontend.Node{Start: 0, End: 1}, nil, unit)
		facts.finish(nil, truncated)
		out, err := facts.result("AST1", 1)
		if err != nil || len(out.Matches) != 1 || out.Truncated != truncated {
			t.Fatalf("semantic limit=%v, got %+v %v", truncated, out, err)
		}
	}
}

func TestPythonFactsEarlierRuleCapSurvivesGlobalFailure(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"AST1", "AST2"}, 1)
	facts.emit("AST1", &frontend.Node{Start: 0, End: 1}, nil, unit)
	facts.emit("AST1", &frontend.Node{Start: 1, End: 2}, nil, unit)
	global := errors.New("global failure")
	facts.finish(global, true)
	capped, err := facts.result("AST1", 10)
	if err != nil || len(capped.Matches) != 1 || !capped.Truncated {
		t.Fatalf("global failure replaced earlier cap: %+v %v", capped, err)
	}
	active, err := facts.result("AST2", 10)
	if !errors.Is(err, global) || len(active.Matches) != 0 || active.Truncated {
		t.Fatalf("active rule lost terminal error: %+v %v", active, err)
	}
}

func TestPythonFactsConcurrentResultsOwnTheirTraces(t *testing.T) {
	t.Parallel()
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	facts := newPythonFacts([]string{"TT1"}, 8)
	facts.emit("TT1", &frontend.Node{Start: 3, End: 5}, &pyOrigin{start: 0, end: 1}, unit)
	facts.finish(nil, false)
	for range 8 {
		t.Run("consumer", func(t *testing.T) {
			t.Parallel()
			first, err := facts.result("TT1", 1)
			if err != nil || len(first.Matches) != 1 || len(first.Matches[0].Trace) != 2 {
				t.Fatalf("invalid shared result: %+v %v", first, err)
			}
			first.Matches[0].Trace[0].Start = 99
			second, err := facts.result("TT1", 1)
			if err != nil || second.Matches[0].Trace[0].Start != 0 {
				t.Fatalf("concurrent result shares trace: %+v %v", second, err)
			}
		})
	}
}

func TestPythonFactsTypedNullAndUnknownRule(t *testing.T) {
	unit := pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10})
	parent, err := frontend.NewNode(frontend.Expr, 0, 0, frontend.ChildField(frontend.FieldValue, nil))
	if err != nil {
		t.Fatal(err)
	}
	facts := newPythonFacts([]string{"AST1"}, 0)
	facts.emit("AST1", parent.Child(frontend.FieldValue), nil, unit)
	facts.emit("AST1", &frontend.Node{Start: 2, End: 2}, nil, unit)
	facts.finish(nil, false)
	out, err := facts.result("AST1", 0)
	if err != nil || len(out.Matches) != 0 || out.Truncated {
		t.Fatalf("null or empty node emitted a candidate: %+v %v", out, err)
	}
	unknown, err := facts.result("unselected", 0)
	if err != nil || len(unknown.Matches) != 0 || unknown.Truncated {
		t.Fatalf("unknown rule produced an outcome: %+v %v", unknown, err)
	}
	if !newPythonFacts(nil, 1).exhausted() {
		t.Fatal("empty selected set cannot do analysis work")
	}
}

func pythonFactsUnit(t *testing.T, original string, span source.Span) document.Unit {
	t.Helper()
	view, err := source.NewView(original, []source.Span{span})
	if err != nil {
		t.Fatal(err)
	}
	return document.Unit{Language: "python", View: view, Span: span}
}
