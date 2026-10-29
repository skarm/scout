package python //nolint:testpackage // Tests exercise private evaluator values and call binding.

import (
	"testing"

	"github.com/skarm/scout/internal/syntax/frontend"
)

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
