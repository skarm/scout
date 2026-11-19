// Exercises private implementation details and package fixtures.
package harness

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func TestNamespaceSelectionPreservesBoundariesAndOrdering(t *testing.T) {
	n := namespace{
		entries: map[string]*entry{},
		names:   []string{"../outside", ".mcp.json", "a", "a-else", "a/b", "a/c", "a0/other", "ab/other", "z"},
	}
	sort.Strings(n.names)
	for _, name := range n.names {
		n.entries[name] = &entry{name: name}
	}
	for _, tc := range []struct {
		name string
		want []string
	}{
		{name: "a", want: []string{"a", "a/b", "a/c"}},
		{name: "a/b", want: []string{"a/b"}},
		{name: "ab", want: []string{"ab/other"}},
		{name: "absent", want: nil},
		{name: ".", want: []string{".mcp.json", "a", "a-else", "a/b", "a/c", "a0/other", "ab/other", "z"}},
	} {
		if got := n.selectNames(tc.name); !reflect.DeepEqual(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
			t.Fatalf("%q: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := n.descendants("."); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestReferencePublicationKeepsBudgetAndTargetGuarantees(t *testing.T) {
	b := builder{
		ctx:        context.Background(),
		r:          report.ComponentGraph{Limits: Limits()},
		references: map[string]bool{},
		issues:     map[string]bool{},
	}
	p := plugin{b: &b, id: "plugin", rootNode: "root"}
	p.reference("", "handler", "resolved", "captured", "target", nil)
	if len(b.r.References) != 0 {
		t.Fatal("orphan reference published")
	}
	p.reference("component", "handler", "resolved", "captured", "", nil)
	p.reference("component", "handler", "resolved", "captured", "", nil)
	if len(b.r.References) != 1 || b.r.References[0].Status != "unresolved" || b.r.References[0].Reason != "component_graph_budget_exceeded" {
		t.Fatal(b.r.References)
	}
	source := &report.SourceRef{Path: "config", ByteStart: 1, ByteEnd: 3}
	p.reference("component", "handler", "resolved", "captured", "target", source)
	if len(b.r.References) != 2 || b.r.References[1].TargetID != "target" {
		t.Fatal(b.r.References)
	}
	b.r.Limits.References = 2
	p.reference("component", "remote", "unresolved", "external", "", source)
	if len(b.r.References) != 2 {
		t.Fatal("reference cap exceeded")
	}
	found := false
	for _, issue := range b.r.Issues {
		if issue.Code == "plugin_reference_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal(b.r.Issues)
	}
}

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
					if !walk.plugin.b.stopped || !commonJSBudgetIssue(walk, "harness_operation_limit") {
						t.Fatalf("%d bindings copied without admission: used=%d stopped=%v", len(bindings), walk.plugin.b.operations, walk.plugin.b.stopped)
					}
				} else if walk.plugin.b.stopped || walk.plugin.b.operations < len(bindings) {
					t.Fatalf("healthy copy uncharged or stopped: used=%d", walk.plugin.b.operations)
				}
				assertCommonJSBudgetBindings(t, bindings, 64)
				if len(walk.plugin.b.hookSourcePaths) != 1 || walk.plugin.b.hookSourcePaths[0].Target != "earlier.js" {
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
					if !walk.plugin.b.stopped || !commonJSBudgetIssue(walk, "harness_operation_limit") {
						t.Fatalf("%s work uncharged: used=%d", operation, walk.plugin.b.operations)
					}
					assertCommonJSBudgetBindings(t, bindings, 64)
				} else if walk.plugin.b.stopped || walk.plugin.b.operations < commonJSMinimumWork(operation, len(bindings)) {
					t.Fatalf("healthy traversal uncharged/stopped: used=%d", walk.plugin.b.operations)
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
	if !walk.plugin.b.stopped || !commonJSBudgetIssue(walk, "harness_cancelled") {
		t.Fatal("empty block ignored cancellation")
	}
	assertCommonJSBudgetBindings(t, bindings, 64)
	retry := commonJSBudgetWalk(t.Context(), 4096)
	retry.inspectBlock(nodeHookModule{}, &scriptsyntax.Node{Kind: "statement_block"}, bindings, nil, 0)
	if retry.plugin.b.stopped || retry.plugin.b.operations < len(bindings) {
		t.Fatal("independent retry failed or uncharged")
	}
}

func commonJSBudgetWalk(ctx context.Context, operations int) *nodeHookWalk {
	limits := Limits()
	limits.Operations = operations
	b := &builder{ctx: ctx, r: report.ComponentGraph{Limits: limits}, issues: map[string]bool{}, hookSourcePaths: []HookSourcePath{{Target: "earlier.js"}}}
	return &nodeHookWalk{hookSourceWalk: &hookSourceWalk{plugin: &plugin{b: b}}, active: map[nodeHookCall]bool{}}
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

func commonJSBudgetIssue(walk *nodeHookWalk, code string) bool {
	for _, issue := range walk.plugin.b.r.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
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
			if !walk.plugin.b.stopped || !commonJSBudgetIssue(walk, "harness_operation_limit") {
				t.Fatal("merge exceeded quota")
			}
			assertCommonJSBudgetBindings(t, bindings, 64)
			walk = commonJSBudgetWalk(t.Context(), 64)
			walk.mergeCells(left, right)
		}
		if walk.plugin.b.stopped || walk.plugin.b.operations != 64 {
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
	if !commonJSBudgetIssue(walk, "harness_cancelled") {
		t.Fatal("merge ignored cancellation")
	}
}

func TestCommonJSShallowFrameRetainsOuterCells(t *testing.T) {
	bindings := commonJSBudgetBindings(2)
	walk := commonJSBudgetWalk(t.Context(), 2)
	child, ok := walk.cloneBindings(bindings)
	if !ok || walk.plugin.b.operations != 2 {
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
			b := &builder{ctx: context.Background(), r: report.ComponentGraph{Limits: Limits()}, issues: map[string]bool{}}
			walk := hookSourceWalk{plugin: &plugin{b: b}}
			file := &entry{name: "setup.sh", meta: report.File{Path: "setup.sh"}}
			run := func(text string, state hookSourceState) hookSourceState {
				tree, err := shellsyntax.ParseDeclarations(b.ctx, text)
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
			if len(parent.functions) != 32 || b.stopped {
				t.Fatalf("setup retained %d definitions, stopped=%v", len(parent.functions), b.stopped)
			}
			b.r.Limits.Operations = b.operations + tc.remaining
			result := run("[ -z '' ] && [ -z '' ]\n", parent)
			if b.stopped != tc.partial || result.traceBlocked != tc.partial {
				t.Fatalf("stopped=%v blocked=%v issues=%v", b.stopped, result.traceBlocked, b.r.Issues)
			}
			if tc.partial {
				if len(b.r.Issues) != 1 || b.r.Issues[0].Code != "harness_operation_limit" || b.r.Issues[0].Status != report.OutcomePartial {
					t.Fatalf("unexpected issues %v", b.r.Issues)
				}
			} else if len(b.r.Issues) != 0 || len(result.functions) != 32 {
				t.Fatalf("lost definitions or unexpected issue: %d, %v", len(result.functions), b.r.Issues)
			}
			if len(parent.functions) != 32 {
				t.Fatalf("branch modified parent: %d definitions", len(parent.functions))
			}
		})
	}
}

func TestShellHookJoinReservesWorkBeforeChangingBindings(t *testing.T) {
	for _, limit := range []int{1, 64} {
		b := &builder{ctx: t.Context(), r: report.ComponentGraph{Limits: Limits()}, issues: map[string]bool{}}
		b.r.Limits.Operations = limit
		walk := hookSourceWalk{plugin: &plugin{b: b}}
		left := walk.commands(nil, source.View{}, nil, hookSourceState{vars: map[string]string{"stable": "one", "left": "two"}}, nil, false)
		right := walk.commands(nil, source.View{}, nil, hookSourceState{vars: map[string]string{"stable": "one", "right": "three"}}, nil, false)
		joined := left.join(right)
		if limit == 1 {
			if !b.stopped || !joined.traceBlocked || left.vars["left"] != "two" || right.vars["right"] != "three" {
				t.Fatalf("failed join changed bindings or remained live: left=%v right=%v", left.vars, right.vars)
			}
			continue
		}
		if b.stopped || joined.traceBlocked || len(joined.vars) != 1 || joined.vars["stable"] != "one" {
			t.Fatalf("healthy join lost the shared binding: %v", joined.vars)
		}
	}
}
