package python //nolint:testpackage // Tests exercise private evaluator values and call binding.

import (
	"slices"
	"testing"

	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestOutputArgumentInspectionPreservesTheSharedSyntaxTree(t *testing.T) {
	call := semanticNode(t, frontend.Call,
		frontend.ChildField(frontend.Func, semanticName(t, "run")),
		frontend.NodesField(frontend.Args, []*frontend.Node{semanticName(t, "command"), semanticName(t, "timeout")}),
		frontend.NodesField(frontend.Keywords, []*frontend.Node{semanticNode(t, frontend.Keyword,
			frontend.TextField(frontend.FieldArg, "input"),
			frontend.ChildField(frontend.FieldValue, semanticName(t, "output")))}))
	arguments := slices.Clone(call.List(frontend.Args))
	for range 2 {
		if !pythonOutputArgument("subprocess.run", call) {
			t.Fatal("output passed through the input keyword was missed")
		}
		if !slices.Equal(call.List(frontend.Args), arguments) {
			t.Fatal("output inspection changed positional arguments visible to other analyzers")
		}
	}
}

func TestCallCapturesCallableBeforeArgumentEffects(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	state.set("run", namedValue("exec"))
	identity := semanticNode(t, frontend.Lambda,
		frontend.ChildField(frontend.Args, semanticNode(t, frontend.Arguments,
			frontend.NodesField(frontend.Args, []*frontend.Node{semanticNode(t, frontend.Arg, frontend.TextField(frontend.FieldArg, "x"))}))),
		frontend.ChildField(frontend.Body, semanticName(t, "x")))
	argument := semanticNode(t, frontend.Call,
		frontend.ChildField(frontend.Func, semanticAssign(t, "run", identity)),
		frontend.NodesField(frontend.Args, []*frontend.Node{semanticNode(t, frontend.Call,
			frontend.ChildField(frontend.Func, semanticName(t, "input")))}))
	w.expr(semanticNode(t, frontend.Call,
		frontend.ChildField(frontend.Func, semanticName(t, "run")),
		frontend.NodesField(frontend.Args, []*frontend.Node{argument})), state, 0)
	assertCallFacts(t, w, false)
}

func TestCallDispatchUsesEvaluatedMappingSymbol(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	state.set("actions", pyValue{meaning: &pyMapping{entries: map[string]pyValue{"run": namedValue("exec")}}})
	function := semanticNode(t, frontend.Subscript,
		frontend.ChildField(frontend.FieldValue, semanticName(t, "actions")),
		frontend.ChildField(frontend.Slice, semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("run")))))
	w.expr(semanticNode(t, frontend.Call,
		frontend.ChildField(frontend.Func, function),
		frontend.NodesField(frontend.Args, []*frontend.Node{semanticNode(t, frontend.Call,
			frontend.ChildField(frontend.Func, semanticName(t, "input")))})), state, 0)
	assertCallFacts(t, w, false)
}

func TestDictionaryEvaluatesKeyBeforeValue(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	value := semanticNode(t, frontend.Call,
		frontend.ChildField(frontend.Func, semanticName(t, "run")),
		frontend.NodesField(frontend.Args, []*frontend.Node{semanticNode(t, frontend.Call,
			frontend.ChildField(frontend.Func, semanticName(t, "input")))}))
	w.expr(semanticNode(t, frontend.Dict,
		frontend.NodesField(frontend.Keys, []*frontend.Node{semanticAssign(t, "run", semanticName(t, "exec"))}),
		frontend.NodesField(frontend.Values, []*frontend.Node{value})), state, 0)
	assertCallFacts(t, w, true)
}

func TestAugmentedAssignmentEvaluatesTargetOnce(t *testing.T) {
	for _, kind := range []frontend.NodeKind{frontend.Attribute, frontend.Subscript} {
		t.Run(kind.String(), func(t *testing.T) {
			w, state := semanticWalker(t), newPyState()
			initial := origin("fixture", semanticName(t, "initial"))
			entries := map[string]pyValue{"original": initial}
			switch kind {
			case frontend.Attribute:
				state.set("container", instanceValue(&pyInstance{fields: entries}))
			case frontend.Subscript:
				state.set("container", pyValue{meaning: &pyMapping{entries: entries}})
			}
			base := semanticAssign(t, "receiver", semanticName(t, "container"))
			right := semanticAssign(t, "receiver", semanticName(t, "updated"))
			state.set("updated", literalValue("updated", true, 2))

			var target *frontend.Node
			if kind == frontend.Attribute {
				target = semanticNode(t, kind, frontend.ChildField(frontend.FieldValue, base), frontend.TextField(frontend.Attr, "original"))
			} else {
				key := semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("original")))
				index := semanticAssign(t, "key", key)
				target = semanticNode(t, kind, frontend.ChildField(frontend.FieldValue, base), frontend.ChildField(frontend.Slice, index))
				right = semanticNode(t, frontend.Tuple, frontend.NodesField(frontend.Elts, []*frontend.Node{
					right, semanticAssign(t, "key", semanticName(t, "updated")),
				}))
			}
			statement := semanticNode(t, frontend.AugAssign, frontend.ChildField(frontend.Target, target), frontend.ChildField(frontend.FieldValue, right))
			w.assignmentStatement(statement, state, 0)

			receiver, _ := state.lookup("receiver")
			if value, _ := receiver.literal(); value != "updated" {
				t.Errorf("receiver after right-hand side = %q, want updated", value)
			}
			if kind == frontend.Subscript {
				key, _ := state.lookup("key")
				if value, _ := key.literal(); value != "updated" {
					t.Errorf("subscript key after right-hand side = %q, want updated", value)
				}
			}
			result := entries["original"]
			if len(result.origins) != 1 || len(result.origins[0].steps) <= len(initial.origins[0].steps) {
				t.Fatal("augmented result was not stored in the original container")
			}
		})
	}
}

func TestSubscriptionKeepsOnlyKnownCallableIdentities(t *testing.T) {
	for _, tc := range []struct {
		name, symbol string
		value        pyValue
		key          *frontend.Node
	}{
		{
			name:   "builtin-dictionary",
			symbol: "builtins.exec",
			value:  namedValue("builtins.__dict__"),
			key:    semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("exec"))),
		},
		{name: "dynamic-reflection", symbol: "", value: namedValue("os.__dict__"), key: semanticName(t, "unknown")},
		{
			name:   "mapping",
			symbol: "exec",
			value:  pyValue{meaning: &pyMapping{entries: map[string]pyValue{"exec": namedValue("exec")}}},
			key:    semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("exec"))),
		},
		{name: "ordinary-symbol", symbol: "", value: namedValue("unknown"), key: semanticName(t, "unknown")},
		{name: "ordinary-literal", symbol: "", value: literalValue("text", true, 2), key: semanticName(t, "unknown")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, state := semanticWalker(t), newPyState()
			state.set("value", tc.value)
			result := w.expr(semanticNode(t, frontend.Subscript,
				frontend.ChildField(frontend.FieldValue, semanticName(t, "value")), frontend.ChildField(frontend.Slice, tc.key)), state, 0)
			if result.symbol() != tc.symbol {
				t.Fatalf("symbol=%q, want %q", result.symbol(), tc.symbol)
			}
		})
	}
}

func TestClassAttributesAreIsolatedByForkAndSharedByAliases(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	class := &pyClass{attrs: map[string]pyValue{"value": namedValue("exec")}}
	class.mro = []*pyClass{class}
	state.set("C", classValue(class))
	state.set("Alias", classValue(class))
	child := state.fork()
	target := semanticNode(t, frontend.Attribute,
		frontend.ChildField(frontend.FieldValue, semanticName(t, "C")), frontend.TextField(frontend.Attr, "value"))
	w.assign(target, namedValue("eval"), child, target)
	alias := semanticNode(t, frontend.Attribute,
		frontend.ChildField(frontend.FieldValue, semanticName(t, "Alias")), frontend.TextField(frontend.Attr, "value"))
	if got := w.expr(alias, child, 0).symbol(); got != "eval" {
		t.Errorf("fork alias lost class mutation: %q", got)
	}
	if got := w.expr(alias, state, 0).symbol(); got != "exec" {
		t.Errorf("fork changed surrounding class: %q", got)
	}
}

func TestMROAcceptsExactlyTheClassLimit(t *testing.T) {
	root := &pyClass{}
	root.mro = pyMRO(root, nil)
	base := root
	for size := 2; size <= maxPythonMROEntries; size++ {
		derived := &pyClass{}
		derived.mro = pyMRO(derived, []*pyClass{base})
		if len(derived.mro) != size || derived.mro[0] != derived || derived.mro[size-1] != root {
			t.Fatalf("MRO length = %d, want %d with the derived and root classes at its ends", len(derived.mro), size)
		}
		base = derived
	}
	if got := pyMRO(&pyClass{}, []*pyClass{base}); got != nil {
		t.Fatalf("MRO length = %d above the limit %d", len(got), maxPythonMROEntries)
	}
}

func TestClassForkPreservesMutableAliasesCyclesAndMethodOwners(t *testing.T) {
	state := newPyState()
	mapping := &pyMapping{entries: map[string]pyValue{}}
	base := &pyClass{attrs: map[string]pyValue{"config": {meaning: mapping}}}
	base.mro = []*pyClass{base}
	method := &pyFunction{owner: base, defaults: map[string]pyValue{"config": {meaning: mapping}}}
	base.attrs["method"] = functionValue(method)
	derived := &pyClass{attrs: map[string]pyValue{}, mro: []*pyClass{nil, base}}
	derived.mro[0] = derived
	mapping.entries["class"] = classValue(base)
	instance := &pyInstance{typ: derived, fields: map[string]pyValue{"config": {meaning: mapping}}}
	method.defaults["instance"] = instanceValue(instance)
	method.defaults["class"] = classValue(derived)
	method.defaults["method"] = functionValue(method).bind(instanceValue(instance))
	state.set("C", classValue(derived))
	state.set("config", pyValue{meaning: mapping})
	state.set("instance", instanceValue(instance))
	state.set("super", superValue(derived, instanceValue(instance)))
	child := state.fork()
	value, ok := pyMember(child.names["C"], "config", child)
	cloned := value.mapping()
	if !ok || cloned == mapping || cloned != child.names["config"].mapping() || cloned != child.names["instance"].instance().fields["config"].mapping() {
		t.Fatal("class attributes lost mutable aliases or share fork contents")
	}
	if cloned.entries["class"].class() != base || child.names["C"].class() != derived {
		t.Fatal("fork changed immutable class identity or a class/container cycle")
	}
	defaults := child.defaultsFor(method)
	defaultReceiver := defaults["method"].bound()
	if defaults["config"].mapping() != cloned || defaults["instance"].instance() != child.names["instance"].instance() || defaultReceiver == nil || defaultReceiver.instance() != child.names["instance"].instance() || defaults["class"].class() != derived {
		t.Fatal("function defaults were cloned outside the class/name/receiver graph")
	}
	if state.defaultsFor(method)["config"].mapping() != mapping {
		t.Fatal("fork changed the defaults of real calls")
	}
	bound, ok := pyMember(child.names["super"], "method", child)
	boundFunction, boundReceiver := bound.function(), bound.bound()
	if !ok || boundFunction == nil || boundFunction != method || boundFunction.owner != base || boundReceiver == nil || boundReceiver.instance() != child.names["instance"].instance() {
		t.Fatal("fork detached super/MRO lookup from its method owner or receiver")
	}
	cloned.entries["new"] = namedValue("new")
	if _, exists := mapping.entries["new"]; exists {
		t.Fatal("class/container alias escaped the fork")
	}
}

func TestClassAttributeBranchMergeSharesOwnersAndAliases(t *testing.T) {
	global := newPyState()
	config := pyValue{meaning: &pyMapping{entries: map[string]pyValue{"run": namedValue("exec")}}}
	class := &pyClass{attrs: map[string]pyValue{"config": config}}
	class.mro = []*pyClass{class}
	instance := &pyInstance{typ: class, fields: map[string]pyValue{}}
	function := &pyFunction{owner: class, defaults: map[string]pyValue{"config": config}}
	class.attrs["method"] = functionValue(function).bind(instanceValue(instance))
	class.attrs["parent"] = superValue(class, instanceValue(instance))
	global.set("C", classValue(class))
	global.set("config", config)
	global.set("instance", instanceValue(instance))
	local := global.scope()
	a, b := local.fork(), local.fork()
	left, _ := pyMember(classValue(class), "config", a)
	right, _ := pyMember(classValue(class), "config", b)
	left.mapping().entries["run"] = pyValue{origins: []pyOrigin{{kind: "input", start: 1, end: 2}}}
	right.mapping().entries["run"] = pyValue{origins: []pyOrigin{{kind: "environment", start: 3, end: 4}}}
	mergePyBranches(local, a, b)
	value, ok := pyMember(classValue(class), "config", global)
	if !ok || value.mapping() != global.names["config"].mapping() || local.objects != global.objects {
		t.Fatal("class attribute merge detached a global alias or scope owner")
	}
	if len(value.mapping().entries["run"].origins) != 2 {
		t.Fatal("class attribute merge lost possible branch sources")
	}
	method, _ := pyMember(classValue(class), "method", global)
	parent, _ := pyMember(classValue(class), "parent", global)
	methodReceiver, parentSuper := method.bound(), parent.super()
	if method.function() != function || methodReceiver == nil || methodReceiver.instance() != global.names["instance"].instance() || parentSuper == nil || parentSuper.owner != class || parentSuper.receiver.instance() != global.names["instance"].instance() {
		t.Fatal("class attribute merge detached bound method/super aliases")
	}
	if global.defaultsFor(function)["config"].mapping() != value.mapping() {
		t.Fatal("branch merge detached function defaults from their class/name alias")
	}
}

func TestMixedBoundnessIsExplicitlyIncomplete(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	function := &pyFunction{lexical: state, defaults: map[string]pyValue{}, node: semanticNode(t, frontend.Lambda,
		frontend.ChildField(frontend.Args, semanticNode(t, frontend.Arguments,
			frontend.NodesField(frontend.Args, []*frontend.Node{semanticNode(t, frontend.Arg, frontend.TextField(frontend.FieldArg, "value"))}))),
		frontend.ChildField(frontend.Body, semanticName(t, "value")))}
	plain := functionValue(function)
	bound := plain.bind(instanceValue(&pyInstance{fields: map[string]pyValue{}}))
	merged := mergePyValue(plain, bound)
	w.invoke(merged, semanticNode(t, frontend.Call), []pyValue{literalValue("input", true, 2)}, nil, state, 0)
	if !w.limited {
		t.Fatal("ambiguous bound/unbound invocation was presented as a definite call")
	}
}

func assertCallFacts(t *testing.T, w *pyWalker, limited bool) {
	t.Helper()
	w.facts.finish(w.err, w.limited)
	for _, id := range []string{"AST1", "TT5"} {
		result, err := w.facts.result(id, 32)
		if err != nil || len(result.Matches) != 1 || result.Truncated != limited {
			t.Errorf("%s: matches=%d partial=%v err=%v", id, len(result.Matches), result.Truncated, err)
		}
	}
}

func TestFunctionDefaultsRemainEquivalentAfterFork(t *testing.T) {
	for _, tc := range []struct {
		name        string
		original    map[string]pyValue
		override    map[string]pyValue
		hasOverride bool
		want        string
	}{
		{name: "nil defaults"},
		{name: "registered nil defaults", hasOverride: true},
		{name: "empty defaults", original: map[string]pyValue{}},
		{name: "registered empty defaults", original: map[string]pyValue{}, override: map[string]pyValue{}, hasOverride: true},
		{name: "original defaults", original: map[string]pyValue{"config": namedValue("original")}, want: "original"},
		{name: "selected override", original: map[string]pyValue{"config": namedValue("original")}, override: map[string]pyValue{"config": namedValue("selected")}, hasOverride: true, want: "selected"},
		{name: "explicit empty override", original: map[string]pyValue{"config": namedValue("original")}, override: map[string]pyValue{}, hasOverride: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPyState()
			function := &pyFunction{lexical: state, defaults: tc.original}
			state.set("function", functionValue(function))
			state.set("alias", functionValue(function))
			if tc.hasOverride {
				state.objects.defaults[function] = tc.override
			}
			child := state.fork()
			grandchild := child.fork()
			merged := mergePy(child, grandchild, map[pyValuePair]pyValue{})
			for _, candidate := range []*pyState{state, child, grandchild, merged} {
				selected := candidate.defaultsFor(function)
				if tc.want == "" {
					if len(selected) != 0 {
						t.Fatalf("empty default selection became populated: %+v", selected)
					}
				} else if len(selected) != 1 || selected["config"].symbol() != tc.want {
					t.Fatalf("default selection changed: got %+v, want %q", selected, tc.want)
				}
				if candidate.names["function"].function() != function || candidate.names["alias"].function() != function {
					t.Fatal("fork changed function identity or its alias")
				}
			}
		})
	}
}

func TestFunctionDefaultMappingAliasesStayInsideFork(t *testing.T) {
	state := newPyState()
	mapping := &pyMapping{entries: map[string]pyValue{"value": namedValue("original")}}
	function := &pyFunction{lexical: state, defaults: map[string]pyValue{"config": {meaning: mapping}}}
	state.set("function", functionValue(function))
	state.set("config", pyValue{meaning: mapping})
	state.objects.defaults[function] = function.defaults
	child := state.fork()
	selected := child.defaultsFor(function)["config"].mapping()
	if selected == nil || selected == mapping || selected != child.names["config"].mapping() {
		t.Fatal("fork detached a default from its alias or retained shared mutable storage")
	}
	selected.entries["value"] = namedValue("changed")
	if child.names["config"].mapping().entries["value"].symbol() != "changed" || state.defaultsFor(function)["config"].mapping().entries["value"].symbol() != "original" {
		t.Fatal("default mutation escaped its fork or lost its alias")
	}
}
