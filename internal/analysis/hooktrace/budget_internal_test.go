package hooktrace

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func TestCommonJSFrameCopiesRespectWorkBudget(t *testing.T) {
	for _, operation := range []string{"block", "function", "catch", "path-return"} {
		t.Run(operation, func(t *testing.T) {
			for _, quota := range []int{2, 4096} {
				walk := commonJSBudgetWalk(t.Context(), quota)
				bindings := commonJSBudgetBindings(64)
				view, err := source.NewView("x", []source.Span{{End: 1}})
				if err != nil {
					t.Fatal(err)
				}
				module := nodeHookModule{unit: document.Unit{View: view}}
				body := &scriptsyntax.Node{Kind: "statement_block", Field: "body"}
				parameter := &scriptsyntax.Node{Kind: "identifier", Start: 0, End: 1}
				fn := &scriptsyntax.Node{Kind: "function_declaration", Children: []*scriptsyntax.Node{{Kind: "formal_parameters", Field: "parameters", Children: []*scriptsyntax.Node{parameter}}, body}}
				switch operation {
				case "block":
					walk.inspectBlock(module, body, bindings, nil, 0)
				case "function":
					walk.inspectFunction(module, fn, nil, &bindings, nil, 0)
				case "catch":
					walk.inspectNode(module, &scriptsyntax.Node{Kind: "catch_clause", Children: []*scriptsyntax.Node{body}}, bindings, nil, 0)
				case "path-return":
					walk.pathReturn(module, nodeHookValue{fn: fn, scope: &bindings}, nodeHookValue{kind: nodeHookText, text: "ordinary"}, 0)
				}
				if quota == 2 {
					if !walk.trace.work.Stopped() || walk.reason != analysisbudget.LimitReached {
						t.Fatalf("%d bindings copied without admission: used=%d stopped=%v", len(bindings), walk.trace.work.Used(), walk.trace.work.Stopped())
					}
				} else if walk.trace.work.Stopped() || walk.trace.work.Used() < len(bindings) {
					t.Fatalf("healthy copy uncharged or stopped: used=%d", walk.trace.work.Used())
				}
				assertCommonJSBudgetBindings(t, bindings, 64)
				if len(walk.trace.sources.Paths) != 1 || walk.trace.sources.Paths[0].Target != "earlier.js" {
					t.Fatal("earlier accepted hook path lost")
				}
				if len(walk.active) != 0 {
					t.Fatal("copy failure leaked active call")
				}
			}
		})
	}
}

func TestCommonJSPredeclarationsAndMergesSpendWork(t *testing.T) {
	for _, operation := range []string{"predeclare", "merge"} {
		t.Run(operation, func(t *testing.T) {
			quota := 2
			if operation == "merge" {
				quota = 128
			}
			for _, limit := range []int{quota, 4096} {
				walk := commonJSBudgetWalk(t.Context(), limit)
				bindings := commonJSBudgetBindings(64)
				if operation == "merge" {
					walk.inspectConditional(nodeHookModule{}, &scriptsyntax.Node{Kind: "if_statement"}, nil, bindings, nil, 0)
				} else {
					var text strings.Builder
					block := &scriptsyntax.Node{Kind: "statement_block"}
					for i := range 64 {
						name := fmt.Sprintf("local_%d", i)
						start := text.Len()
						text.WriteString(name)
						text.WriteByte(' ')
						block.Children = append(block.Children, &scriptsyntax.Node{Kind: "function_declaration", Children: []*scriptsyntax.Node{{Kind: "identifier", Field: "name", Start: start, End: start + len(name)}}})
					}
					view, err := source.NewView(text.String(), []source.Span{{End: text.Len()}})
					if err != nil {
						t.Fatal(err)
					}
					walk.predeclare(nodeHookModule{unit: document.Unit{View: view}}, block, bindings)
				}
				if limit == quota {
					if !walk.trace.work.Stopped() || walk.reason != analysisbudget.LimitReached {
						t.Fatalf("%s work uncharged: used=%d", operation, walk.trace.work.Used())
					}
					assertCommonJSBudgetBindings(t, bindings, 64)
				} else if walk.trace.work.Stopped() || walk.trace.work.Used() < commonJSMinimumWork(operation, len(bindings)) {
					t.Fatalf("healthy traversal uncharged/stopped: used=%d", walk.trace.work.Used())
				}
			}
		})
	}
}

func TestCommonJSFrameCancellationPreservesState(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	walk := commonJSBudgetWalk(ctx, 4096)
	bindings := commonJSBudgetBindings(64)
	walk.inspectBlock(nodeHookModule{}, &scriptsyntax.Node{Kind: "statement_block"}, bindings, nil, 0)
	if !walk.trace.work.Stopped() || walk.reason != analysisbudget.Cancelled {
		t.Fatal("empty block ignored cancellation")
	}
	assertCommonJSBudgetBindings(t, bindings, 64)
	retry := commonJSBudgetWalk(t.Context(), 4096)
	retry.inspectBlock(nodeHookModule{}, &scriptsyntax.Node{Kind: "statement_block"}, bindings, nil, 0)
	if retry.trace.work.Stopped() || retry.trace.work.Used() < len(bindings) {
		t.Fatal("independent retry failed or uncharged")
	}
}

type budgetNodeWalk struct {
	*nodeHookWalk
	reason analysisbudget.StopReason
}

func commonJSBudgetWalk(ctx context.Context, operations int) *budgetNodeWalk {
	walk := &budgetNodeWalk{}
	work := &analysisbudget.Sequence{
		Context: ctx,
		Limit:   operations,
		OnStop:  func(reason analysisbudget.StopReason) { walk.reason = reason },
	}
	trace := &Tracer{work: work, sources: Sources{Paths: []Path{{Target: "earlier.js"}}}}
	walk.nodeHookWalk = &nodeHookWalk{hookSourceWalk: &hookSourceWalk{trace: trace}, active: map[nodeHookCall]bool{}}

	return walk
}

func commonJSBudgetBindings(count int) nodeHookBindings {
	bindings := make(nodeHookBindings)
	for i := range count {
		bindings.bind(fmt.Sprintf("local_%d", i), nodeHookValue{kind: nodeHookText, text: "ordinary"})
	}
	return bindings
}

func assertCommonJSBudgetBindings(t *testing.T, bindings nodeHookBindings, count int) {
	t.Helper()
	if len(bindings) != count {
		t.Fatal("partial state published")
	}
	for _, value := range bindings {
		if value.kind != nodeHookText || value.text != "ordinary" {
			t.Fatal("original cell changed")
		}
	}
}

func TestCommonJSCellMergeAdmissionIsAtomic(t *testing.T) {
	for _, quota := range []int{63, 64} {
		bindings := commonJSBudgetBindings(64)
		left, right := map[*nodeHookValue]*nodeHookValue{}, map[*nodeHookValue]*nodeHookValue{}
		for i := range 64 {
			cell := bindings[fmt.Sprintf("local_%d", i)]
			branch := left
			if i >= 32 {
				branch = right
			}
			branch[cell] = &nodeHookValue{}
		}
		walk := commonJSBudgetWalk(t.Context(), quota)
		walk.mergeCells(left, right)
		if quota == 63 {
			if !walk.trace.work.Stopped() || walk.reason != analysisbudget.LimitReached {
				t.Fatal("merge exceeded quota")
			}
			assertCommonJSBudgetBindings(t, bindings, 64)
			walk = commonJSBudgetWalk(t.Context(), 64)
			walk.mergeCells(left, right)
		}
		if walk.trace.work.Stopped() || walk.trace.work.Used() != 64 {
			t.Fatal("exact merge admission failed")
		}
		for _, cell := range bindings {
			if cell.kind != nodeHookUnknown {
				t.Fatal("admitted merge lost invalidation")
			}
		}
	}
	bindings := commonJSBudgetBindings(1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	walk := commonJSBudgetWalk(ctx, 64)
	walk.mergeCells(map[*nodeHookValue]*nodeHookValue{bindings["local_0"]: {}}, nil)
	assertCommonJSBudgetBindings(t, bindings, 1)
	if walk.reason != analysisbudget.Cancelled {
		t.Fatal("merge ignored cancellation")
	}
}

func TestCommonJSShallowFrameRetainsOuterCells(t *testing.T) {
	bindings := commonJSBudgetBindings(2)
	walk := commonJSBudgetWalk(t.Context(), 2)
	child, ok := walk.cloneBindings(bindings)
	if !ok || walk.trace.work.Used() != 2 {
		t.Fatal("exact clone admission failed")
	}
	child.invalidate("local_0")
	child.bind("local_1", nodeHookValue{})
	if bindings["local_0"].kind != nodeHookUnknown || bindings["local_1"].kind != nodeHookText {
		t.Fatal("outer cells or local shadowing changed")
	}
}

func commonJSMinimumWork(operation string, names int) int {
	if operation == "merge" {
		return 4 * names
	}
	return 2 * names
}

func TestShellHookBranchesRespectRemainingGraphWork(t *testing.T) {
	var declarations strings.Builder
	for i := range 32 {
		fmt.Fprintf(&declarations, "name%d() { :; }\n", i)
	}

	for _, tc := range []struct {
		name      string
		remaining int
		partial   bool
	}{
		{"limited", 8, true},
		{"sufficient", 1024, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reasons []analysisbudget.StopReason
			work := &analysisbudget.Sequence{
				Context: t.Context(), Limit: 500_000,
				OnStop: func(reason analysisbudget.StopReason) { reasons = append(reasons, reason) },
			}
			walk := hookSourceWalk{trace: &Tracer{work: work}}
			file := &File{Meta: report.File{Path: "setup.sh"}}
			run := func(text string, state hookSourceState) hookSourceState {
				tree, err := shellsyntax.ParseDeclarations(work.Context, text)
				if err != nil {
					t.Fatal(err)
				}
				view, err := source.NewView(text, []source.Span{{End: len(text)}})
				if err != nil {
					t.Fatal(err)
				}
				return walk.commands(file, view, tree, state, nil, false)
			}

			parent := run(declarations.String(), hookSourceState{})
			if len(parent.functions) != 32 || work.Stopped() {
				t.Fatalf("setup retained %d definitions, stopped=%v", len(parent.functions), work.Stopped())
			}
			work.Limit = work.Used() + tc.remaining
			result := run("[ -z '' ] && [ -z '' ]\n", parent)
			if work.Stopped() != tc.partial || result.traceBlocked != tc.partial {
				t.Fatalf("stopped=%v blocked=%v issues=%v", work.Stopped(), result.traceBlocked, reasons)
			}
			if tc.partial {
				if len(reasons) != 1 || reasons[0] != analysisbudget.LimitReached {
					t.Fatalf("unexpected issues %v", reasons)
				}
			} else if len(reasons) != 0 || len(result.functions) != 32 {
				t.Fatalf("lost definitions or unexpected issue: %d, %v", len(result.functions), reasons)
			}
			if len(parent.functions) != 32 {
				t.Fatalf("branch modified parent: %d definitions", len(parent.functions))
			}
		})
	}
}

func TestShellHookJoinReservesWorkBeforeChangingBindings(t *testing.T) {
	for _, limit := range []int{1, 64} {
		work := &analysisbudget.Sequence{Context: t.Context(), Limit: limit}
		walk := hookSourceWalk{trace: &Tracer{work: work}}
		left := walk.commands(nil, source.View{}, nil, hookSourceState{vars: map[string]string{"stable": "one", "left": "two"}}, nil, false)
		right := walk.commands(nil, source.View{}, nil, hookSourceState{vars: map[string]string{"stable": "one", "right": "three"}}, nil, false)
		joined := left.join(right)
		if limit == 1 {
			if !work.Stopped() || !joined.traceBlocked || left.vars["left"] != "two" || right.vars["right"] != "three" {
				t.Fatalf("failed join changed bindings or remained live: left=%v right=%v", left.vars, right.vars)
			}
			continue
		}
		if work.Stopped() || joined.traceBlocked || len(joined.vars) != 1 || joined.vars["stable"] != "one" {
			t.Fatalf("healthy join lost the shared binding: %v", joined.vars)
		}
	}
}
