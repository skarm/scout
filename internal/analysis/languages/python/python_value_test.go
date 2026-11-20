package python //nolint:testpackage // Tests exercise private value graphs, aliases and bounded merges.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestForkSeparatesMutableContentsAndPreservesAliases(t *testing.T) {
	mapping := &pyMapping{entries: map[string]pyValue{}}
	value := pyValue{meaning: mapping}
	mapping.entries["self"] = value
	instance := &pyInstance{fields: map[string]pyValue{"config": value}}
	function := &pyFunction{}
	bound := functionValue(function).bind(instanceValue(instance))
	sequence := pyValue{meaning: &pySequence{items: []pyValue{value, instanceValue(instance)}}}
	original := newPyState()
	original.names = map[string]pyValue{
		"one":            value,
		"two":            value,
		"receiver":       instanceValue(instance),
		"method":         bound,
		"sequence":       sequence,
		"sequence_alias": sequence,
	}
	fork := original.fork()
	cloned := fork.names["one"].mapping()
	if cloned == mapping || cloned != fork.names["two"].mapping() || cloned.entries["self"].mapping() != cloned {
		t.Fatal("fork lost a container cycle or alias, or shares mutable contents")
	}
	receiver := fork.names["receiver"].instance()
	method := fork.names["method"]
	boundReceiver := method.bound()
	if receiver == nil || receiver == instance || method.function() != function || boundReceiver == nil || boundReceiver.instance() != receiver || receiver.fields["config"].mapping() != cloned {
		t.Fatal("fork changed method identity or detached the bound receiver from its aliases")
	}
	items := fork.names["sequence"].elements()
	if items[0].mapping() != cloned || items[1].instance() != receiver || &items[0] != &fork.names["sequence_alias"].elements()[0] {
		t.Fatal("fork lost sequence element aliases")
	}
	cloned.entries["new"] = namedValue("new")
	if _, exists := mapping.entries["new"]; exists {
		t.Fatal("hypothetical branch mutated the original mapping")
	}
}

func TestBranchMergeKeepsOneMeaningAndIndependentTaint(t *testing.T) {
	left := namedValue("os.system")
	left.origins = []pyOrigin{{kind: "input", start: 1, end: 2}}
	right := namedValue("os.system")
	right.origins = []pyOrigin{{kind: "environment", start: 3, end: 4}}
	if merged := mergePyValue(left, right); merged.symbol() != "os.system" || len(merged.origins) != 2 {
		t.Fatal("compatible symbol lost identity or branch taint")
	}
	if merged := mergePyValue(left, classValue(&pyClass{})); merged.meaning != nil || len(merged.origins) != 1 {
		t.Fatal("incompatible meanings were combined or taint was discarded")
	}
	empty := literalValue("", true, 1)
	if text, known := mergePyValue(empty, empty).literal(); !known || text != "" {
		t.Fatal("known empty literal became unknown")
	}
	if _, known := mergePyValue(empty, pyValue{}).literal(); known {
		t.Fatal("unknown branch became a known literal")
	}
	function := &pyFunction{}
	callable := functionValue(function)
	a, b := callable.bind(classValue(&pyClass{})), callable.bind(classValue(&pyClass{}))
	merged := mergePyValue(a, b)
	boundReceiver := merged.bound()
	if merged.function() != function || boundReceiver == nil || boundReceiver.meaning != nil {
		t.Fatal("different possible receivers lost known boundness or became one definite receiver")
	}
}

func TestMappingBranchMergeRetainsCycleAndJoinsContentTaint(t *testing.T) {
	a, b := &pyMapping{entries: map[string]pyValue{}}, &pyMapping{entries: map[string]pyValue{}}
	x, y := pyValue{meaning: a}, pyValue{meaning: b}
	a.entries["self"], b.entries["self"] = x, y
	a.entries["value"] = pyValue{origins: []pyOrigin{{kind: "input", start: 1, end: 2}}}
	b.entries["value"] = pyValue{origins: []pyOrigin{{kind: "environment", start: 3, end: 4}}}
	merged := pyContents(mergePyValue(x, y))
	if merged.mapping() == a || merged.mapping() == b || merged.mapping().entries["self"].mapping() != merged.mapping() || len(merged.origins) != 2 {
		t.Fatal("branch merge lost cyclic identity or current content taint")
	}
}

func TestTransformKeepsCallableIdentityAndOwnsTrace(t *testing.T) {
	function := &pyFunction{}
	value := functionValue(function).bind(classValue(&pyClass{}))
	value.origins = []pyOrigin{{kind: "input", start: 0, end: 1}}
	transformed := transformed(value, &frontend.Node{Start: 4, End: 8})
	if transformed.function() != function || transformed.bound() != value.bound() || len(transformed.origins[0].steps) != 1 || len(value.origins[0].steps) != 0 {
		t.Fatal("source transformation changed semantic identity or shared mutable trace")
	}
}

func TestStateForkMergeChargesActualEntries(t *testing.T) {
	for _, quota := range []uint64{2, 4096} {
		t.Run(strconv.FormatUint(quota, 10), func(t *testing.T) {
			state := newPyState()
			for i := range 64 {
				state.set(fmt.Sprintf("local_%d", i), literalValue("ordinary", true, 2))
			}
			walk := semanticWalker(t)
			walk.ctx = analysisbudget.WithLimit(t.Context(), quota)
			conditional := semanticNode(t, frontend.If, frontend.ChildField(frontend.Test, semanticName(t, "unknown_condition")), frontend.NodesField(frontend.Body, nil), frontend.NodesField(frontend.Orelse, nil))
			walk.block([]*frontend.Node{conditional}, state, 0)
			if quota == 2 {
				if !walk.truncated || !analysisbudget.Exhausted(walk.ctx) {
					t.Fatalf("state work escaped quota: used=%d truncated=%v err=%v", analysisbudget.Used(walk.ctx), walk.truncated, walk.err)
				}
			} else if walk.err != nil || walk.truncated || analysisbudget.Used(walk.ctx) < uint64(3*len(state.names)) {
				t.Fatalf("admitted state work failed or uncharged: used=%d truncated=%v err=%v", analysisbudget.Used(walk.ctx), walk.truncated, walk.err)
			}
			if len(state.names) != 64 {
				t.Fatal("failed exploration published a partial namespace")
			}
			for _, value := range state.names {
				if text, known := value.literal(); !known || text != "ordinary" {
					t.Fatal("exploration changed original values")
				}
			}
		})
	}
}

func TestStateMergePublishesAllOwnersOrNone(t *testing.T) {
	// First obtain a successful result, then stop at each preceding admission.
	// The assertion is atomic publication, independent of traversal order/cost.
	walk := semanticWalker(t)
	walk.ctx = analysisbudget.WithLimit(t.Context(), 4096)
	state, a, b, class := stateMergeFixture()
	walk.mergeBranches(state, a, b)
	assertMergedState(t, state, class, "after")
	if walk.err != nil || walk.truncated {
		t.Fatalf("healthy merge failed: %v/%v", walk.err, walk.truncated)
	}
	used := analysisbudget.Used(walk.ctx)
	for quota := uint64(1); quota < used; quota++ {
		t.Run(strconv.FormatUint(quota, 10), func(t *testing.T) {
			state, a, b, class := stateMergeFixture()
			walk := semanticWalker(t)
			walk.ctx = analysisbudget.WithLimit(t.Context(), quota)
			walk.mergeBranches(state, a, b)
			if !walk.truncated || !analysisbudget.Exhausted(walk.ctx) {
				t.Fatalf("partial merge escaped quota: used=%d err=%v", analysisbudget.Used(walk.ctx), walk.err)
			}
			assertMergedState(t, state, class, "before")
			// A fresh caller can retry against the unchanged state.
			retry := semanticWalker(t)
			retry.ctx = analysisbudget.WithLimit(t.Context(), 4096)
			retry.mergeBranches(state, a, b)
			assertMergedState(t, state, class, "after")
			if retry.err != nil || retry.truncated {
				t.Fatal("failed merge poisoned a subsequent caller")
			}
		})
	}
}

func stateMergeFixture() (*pyState, *pyState, *pyState, *pyClass) {
	global := newPyState()
	global.set("global_value", namedValue("before"))
	parent := global.scope()
	parent.set("parent_value", namedValue("before"))
	state := parent.scope()
	state.set("local_value", namedValue("before"))
	class := &pyClass{attrs: map[string]pyValue{"attribute": namedValue("before")}}
	state.objects.classes[class] = class.attrs
	a, b := state.fork(), state.fork()
	for _, branch := range []*pyState{a, b} {
		branch.names["local_value"] = namedValue("after")
		branch.parent.names["parent_value"] = namedValue("after")
		branch.global.names["global_value"] = namedValue("after")
		branch.objects.classes[class] = map[string]pyValue{"attribute": namedValue("after")}
	}
	return state, a, b, class
}

func assertMergedState(t *testing.T, state *pyState, class *pyClass, want string) {
	t.Helper()
	if state.names["local_value"].symbol() != want || state.parent.names["parent_value"].symbol() != want || state.global.names["global_value"].symbol() != want || state.objects.classes[class]["attribute"].symbol() != want {
		t.Fatalf("namespace/owner/object publication was not atomic; want %q", want)
	}
}

type stateCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *stateCancelContext) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestStateForkCancellationPreservesOriginalAndEarlierFacts(t *testing.T) {
	state := newPyState()
	for i := range 64 {
		state.set(fmt.Sprintf("local_%d", i), namedValue("before"))
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	walk := semanticWalker(t)
	walk.ctx = &stateCancelContext{Context: ctx, cancel: cancel, remaining: 8}
	walk.facts.outputs[ruleAST1].Add(check.Match{Start: 1, End: 2})
	child := walk.forkState(state)
	if !errors.Is(walk.err, context.Canceled) || walk.truncated || len(child.names) != 0 || len(child.locals) != 0 {
		t.Fatalf("cancelled fork published state or lost error: names=%d locals=%d err=%v truncated=%v", len(child.names), len(child.locals), walk.err, walk.truncated)
	}
	child.set("local_0", namedValue("changed"))
	if len(state.names) != 64 || state.names["local_0"].symbol() != "before" {
		t.Fatal("failed fork mutated its original")
	}
	walk.facts.finish(walk.err, walk.truncated)
	result, err := walk.facts.result(ruleAST1, 32)
	if !errors.Is(err, context.Canceled) || result.Truncated || len(result.Matches) != 1 || result.Matches[0].Start != 1 || result.Matches[0].End != 2 {
		t.Fatalf("cancellation lost prefix facts: %+v / %v", result, err)
	}
	retry := semanticWalker(t)
	retry.ctx = analysisbudget.WithLimit(t.Context(), 4096)
	recovered := retry.forkState(state)
	if retry.err != nil || retry.truncated || len(recovered.names) != 64 || recovered.names["local_0"].symbol() != "before" {
		t.Fatal("cancelled fork poisoned an independent retry")
	}
}

func TestStateMergeCancellationDoesNotPublishOwners(t *testing.T) {
	state, a, b, class := stateMergeFixture()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	walk := semanticWalker(t)
	walk.ctx = &stateCancelContext{Context: ctx, cancel: cancel, remaining: 12}
	walk.mergeBranches(state, a, b)
	if !errors.Is(walk.err, context.Canceled) || walk.truncated {
		t.Fatalf("merge lost cancellation: err=%v truncated=%v", walk.err, walk.truncated)
	}
	assertMergedState(t, state, class, "before")
}

func TestValueMergeDoesNotReturnPartialContainers(t *testing.T) {
	left := &pyMapping{entries: map[string]pyValue{}}
	right := &pyMapping{entries: map[string]pyValue{}}
	for i := range 64 {
		name := fmt.Sprintf("entry_%d", i)
		left.entries[name], right.entries[name] = namedValue("ordinary"), namedValue("ordinary")
	}
	for _, quota := range []uint64{8, 4096} {
		t.Run(strconv.FormatUint(quota, 10), func(t *testing.T) {
			walk := semanticWalker(t)
			walk.ctx = analysisbudget.WithLimit(t.Context(), quota)
			merged := walk.mergeValues(pyValue{meaning: left}, pyValue{meaning: right})
			if quota == 8 {
				if !walk.truncated || !analysisbudget.Exhausted(walk.ctx) || merged.meaning != nil {
					t.Fatal("failed merge exposed a partial container")
				}
			} else if walk.err != nil || walk.truncated || merged.mapping() == nil || len(merged.mapping().entries) != 64 || merged.mapping().entries["entry_0"].symbol() != "ordinary" {
				t.Fatal("healthy merge lost a container or its values")
			}
			if len(left.entries) != 64 || len(right.entries) != 64 || left.entries["entry_0"].symbol() != "ordinary" || right.entries["entry_0"].symbol() != "ordinary" {
				t.Fatal("merge modified an input container")
			}
		})
	}
}

func TestBudgetedForkKeepsDefaultAliasesInsideEachBranch(t *testing.T) {
	state := newPyState()
	mapping := &pyMapping{entries: map[string]pyValue{"value": namedValue("original")}}
	function := &pyFunction{lexical: state, defaults: map[string]pyValue{"config": namedValue("overridden")}}
	state.objects.defaults[function] = map[string]pyValue{"config": {meaning: mapping}}
	state.set("function", functionValue(function))
	state.set("config", pyValue{meaning: mapping})
	walk := semanticWalker(t)
	walk.ctx = analysisbudget.WithLimit(t.Context(), 4096)
	child, sibling := walk.forkState(state), walk.forkState(state)
	grandchild := walk.forkState(child)
	for _, candidate := range []*pyState{child, sibling, grandchild} {
		selected := candidate.defaultsFor(function)["config"].mapping()
		if selected == nil || selected == mapping || selected != candidate.names["config"].mapping() || candidate.names["function"].function() != function {
			t.Fatal("budgeted fork lost default selection, alias, or immutable function identity")
		}
	}
	grandchild.defaultsFor(function)["config"].mapping().entries["value"] = namedValue("changed")
	for _, candidate := range []*pyState{state, child, sibling} {
		if candidate.defaultsFor(function)["config"].mapping().entries["value"].symbol() != "original" {
			t.Fatal("default mutation escaped into an ancestor or sibling")
		}
	}
	merged := walk.mergeStates(child, sibling)
	selected := merged.defaultsFor(function)["config"].mapping()
	if walk.err != nil || walk.truncated || selected == nil || selected != merged.names["config"].mapping() || selected.entries["value"].symbol() != "original" {
		t.Fatal("budgeted merge lost default selection or alias")
	}
}

func TestInvocationChargesDefaultScopeCopy(t *testing.T) {
	state := newPyState()
	parameters := make([]*frontend.Node, 64)
	defaults := map[string]pyValue{}
	for i := range parameters {
		name := fmt.Sprintf("parameter_%d", i)
		parameters[i] = semanticNode(t, frontend.Arg, frontend.TextField(frontend.FieldArg, name))
		defaults[name] = namedValue("ordinary")
	}
	arguments := semanticNode(t, frontend.Arguments, frontend.NodesField(frontend.Args, parameters))
	node := semanticNode(t, frontend.Lambda, frontend.ChildField(frontend.Args, arguments), frontend.ChildField(frontend.Body, semanticName(t, "parameter_0")))
	function := &pyFunction{node: node, lexical: state, defaults: defaults}
	selected := &pyMapping{entries: map[string]pyValue{"value": namedValue("selected")}}
	state.objects.defaults[function] = map[string]pyValue{}
	maps.Copy(state.objects.defaults[function], defaults)
	state.objects.defaults[function]["parameter_0"] = pyValue{meaning: selected}
	for _, quota := range []uint64{8, 4096} {
		t.Run(strconv.FormatUint(quota, 10), func(t *testing.T) {
			walk := semanticWalker(t)
			walk.ctx = analysisbudget.WithLimit(t.Context(), quota)
			value := walk.invoke(functionValue(function), nil, nil, nil, state, 0)
			if quota == 8 {
				if !walk.truncated || !analysisbudget.Exhausted(walk.ctx) || value.meaning != nil {
					t.Fatalf("defaults copy escaped quota: used=%d value=%+v truncated=%v", analysisbudget.Used(walk.ctx), value, walk.truncated)
				}
			} else if walk.err != nil || walk.truncated || value.mapping() != selected || analysisbudget.Used(walk.ctx) < 64 {
				t.Fatalf("default alias/selection or work accounting changed: used=%d value=%+v err=%v", analysisbudget.Used(walk.ctx), value, walk.err)
			}
			if len(walk.frames) != 0 || len(walk.active) != 0 || len(state.names) != 0 || defaults["parameter_0"].symbol() != "ordinary" || selected.entries["value"].symbol() != "selected" {
				t.Fatal("invocation changed defaults/outer scope or leaked an active frame")
			}
		})
	}
}
