package python //nolint:testpackage // Tests exercise private interpreter state and semantic boundaries.

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestConditionalExpressionCommitsOnlyThePossibleBranch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition pyValue
		want      string
		known     bool
	}{
		{name: "true", condition: literalValue("", false, 2), want: "left", known: true},
		{name: "false", condition: literalValue("", false, 1), want: "right", known: true},
		{name: "unknown", condition: pyValue{}, want: "", known: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, s := semanticWalker(t), semanticState()
			s.set("condition", tc.condition)
			n := semanticNode(t, frontend.IfExp,
				frontend.ChildField(frontend.Test, semanticName(t, "condition")),
				frontend.ChildField(frontend.Body, semanticAssign(t, "chosen", semanticName(t, "left"))),
				frontend.ChildField(frontend.Orelse, semanticAssign(t, "chosen", semanticName(t, "right"))))
			value := w.expr(n, s, 0)
			text, known := value.literal()
			assigned, _ := s.lookup("chosen")
			stored, storedKnown := assigned.literal()
			if text != tc.want || known != tc.known || stored != tc.want || storedKnown != tc.known {
				t.Fatalf("value=%q/%v stored=%q/%v", text, known, stored, storedKnown)
			}
		})
	}
}

func TestBooleanShortCircuitAndUnknownBranchEffects(t *testing.T) {
	for _, tc := range []struct {
		op             string
		truth          uint8
		want, assigned bool
	}{
		{op: "And", truth: 1, want: false, assigned: false}, {op: "And", truth: 2, want: true, assigned: true}, {
			op:       "Or",
			truth:    2,
			want:     false,
			assigned: false,
		}, {
			op:       "Or",
			truth:    1,
			want:     true,
			assigned: true,
		}, {
			op:       "And",
			truth:    0,
			want:     false,
			assigned: true,
		}, {
			op:       "Or",
			truth:    0,
			want:     false,
			assigned: true,
		},
	} {
		w, s := semanticWalker(t), semanticState()
		s.set("condition", pyValue{truth: tc.truth})
		n := semanticNode(t, frontend.BoolOp, frontend.TextField(frontend.Op, tc.op), frontend.NodesField(frontend.Values, []*frontend.Node{
			semanticName(t, "condition"), semanticAssign(t, "chosen", semanticName(t, "right")),
		}))
		result := w.expr(n, s, 0)
		text, known := result.literal()
		_, assigned := s.lookup("chosen")
		if known != tc.want || tc.want && text != "right" || assigned != tc.assigned {
			t.Fatalf("%s/%d result=%q/%v assigned=%v", tc.op, tc.truth, text, known, assigned)
		}
	}
	empty := semanticNode(t, frontend.BoolOp)
	if got := semanticWalker(t).expr(empty, newPyState(), 0); got.meaning != nil || len(got.origins) != 0 {
		t.Fatal("empty boolean expression invented a value")
	}
}

func TestTryMergesHandlerSourcesAndRunsFinally(t *testing.T) {
	w, s := semanticWalker(t), semanticState()
	s.set("input_value", pyValue{origins: []pyOrigin{{kind: "input", start: 1, end: 2}}})
	s.set("environment_value", pyValue{origins: []pyOrigin{{kind: "environment", start: 3, end: 4}}})
	handler := semanticNode(t, frontend.ExceptHandler, frontend.TextField(frontend.FieldName, "error"), frontend.NodesField(frontend.Body, []*frontend.Node{
		semanticAssign(t, "chosen", semanticName(t, "environment_value")),
	}))
	n := semanticNode(t, frontend.Try,
		frontend.NodesField(frontend.Body, []*frontend.Node{semanticAssign(t, "chosen", semanticName(t, "input_value"))}),
		frontend.NodesField(frontend.Orelse, []*frontend.Node{semanticAssign(t, "success", semanticName(t, "left"))}),
		frontend.NodesField(frontend.Handlers, []*frontend.Node{handler}),
		frontend.NodesField(frontend.Finalbody, []*frontend.Node{semanticAssign(t, "finished", semanticName(t, "right"))}))
	w.block([]*frontend.Node{n}, s, 0)
	value, _ := s.lookup("chosen")
	finished, _ := s.lookup("finished")
	if len(value.origins) != 2 {
		t.Fatalf("handler sources were lost: %+v", value.origins)
	}
	if text, known := finished.literal(); !known || text != "right" {
		t.Fatal("finally did not run")
	}
	if value, _ := s.lookup("error"); value.meaning != nil || len(value.origins) != 0 {
		t.Fatal("exception target acquired a definite value outside its branch")
	}
}

func TestHandlerOriginsWalksCapturedFieldsWithoutFollowingCycles(t *testing.T) {
	a, b := &pyInstance{fields: map[string]pyValue{}}, &pyInstance{fields: map[string]pyValue{}}
	a.fields["next"] = instanceValue(b)
	b.fields["previous"] = instanceValue(a)
	b.fields["secret"] = pyValue{origins: []pyOrigin{{kind: "environment", start: 1, end: 2}}}
	value := pyHandlerOrigins(instanceValue(a), 0, map[*pyInstance]bool{})
	if len(value.origins) != 1 || value.origins[0].kind != "environment" {
		t.Fatal("captured handler credential lost")
	}
	if got := pyHandlerOrigins(instanceValue(a), 9, map[*pyInstance]bool{}); len(got.origins) != 0 {
		t.Fatal("handler recursion limit ignored")
	}
	if got := pyHandlerOrigins(literalValue("plain", true, 2), 0, map[*pyInstance]bool{}); got.meaning != nil {
		t.Fatal("handler inspection leaked unrelated value semantics")
	}
}

func TestWalkerStopsAtCancellationAndOperationAndDepthBudgets(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	w := semanticWalker(t)
	w.ctx = canceled
	if w.charge(0) || !errors.Is(w.err, context.Canceled) {
		t.Fatal("cancellation was ignored")
	}
	w = semanticWalker(t)
	w.ctx = analysisbudget.WithLimit(context.Background(), 1)
	if !w.charge(0) || w.charge(0) || !w.truncated {
		t.Fatal("shared operation budget was ignored")
	}
	w = semanticWalker(t)
	if w.charge(65) || !w.truncated {
		t.Fatal("depth budget was ignored")
	}
	w = semanticWalker(t)
	w.ops = 100000
	if w.charge(0) || !w.truncated {
		t.Fatal("local operation budget was ignored")
	}
	w = semanticWalker(t)
	w.facts = newPythonFacts(nil, 1)
	if w.charge(0) {
		t.Fatal("exhausted selected rules consumed more work")
	}
}

func TestTruthUsesOnlyKnownScalarAndContainerValues(t *testing.T) {
	constant := func(value frontend.Value) *frontend.Node {
		return semanticNode(t, frontend.Constant, frontend.LiteralField(value))
	}
	item := constant(frontend.StringValue("x"))
	star := semanticNode(t, frontend.Starred, frontend.ChildField(frontend.FieldValue, item))
	for _, tc := range []struct {
		name  string
		node  *frontend.Node
		truth uint8
	}{
		{name: "null", node: constant(frontend.NullValue()), truth: 1},
		{name: "false", node: constant(frontend.BoolValue(false)), truth: 1},
		{name: "true", node: constant(frontend.BoolValue(true)), truth: 2},
		{name: "empty-string", node: constant(frontend.StringValue("")), truth: 1},
		{name: "text", node: item, truth: 2},
		{name: "bytes-unmodeled", node: constant(frontend.BytesValue([]byte("x"))), truth: 0},
		{name: "empty-list", node: semanticNode(t, frontend.List), truth: 1},
		{
			name:  "list",
			node:  semanticNode(t, frontend.List, frontend.NodesField(frontend.Elts, []*frontend.Node{item})),
			truth: 2,
		},
		{
			name:  "starred-list",
			node:  semanticNode(t, frontend.List, frontend.NodesField(frontend.Elts, []*frontend.Node{star})),
			truth: 0,
		},
		{name: "empty-dict", node: semanticNode(t, frontend.Dict), truth: 1},
		{
			name:  "dict",
			node:  semanticNode(t, frontend.Dict, frontend.NodesField(frontend.Keys, []*frontend.Node{item})),
			truth: 2,
		},
		{
			name:  "dict-spread",
			node:  semanticNode(t, frontend.Dict, frontend.NodesField(frontend.Keys, []*frontend.Node{nil})),
			truth: 0,
		},
		{
			name:  "not",
			node:  semanticNode(t, frontend.UnaryOp, frontend.TextField(frontend.Op, "Not"), frontend.ChildField(frontend.Operand, item)),
			truth: 1,
		},
		{
			name:  "minus",
			node:  semanticNode(t, frontend.UnaryOp, frontend.TextField(frontend.Op, "USub"), frontend.ChildField(frontend.Operand, item)),
			truth: 2,
		},
		{
			name:  "invert-unknown",
			node:  semanticNode(t, frontend.UnaryOp, frontend.TextField(frontend.Op, "Invert"), frontend.ChildField(frontend.Operand, item)),
			truth: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pyTruth(tc.node, newPyState(), 0); got != tc.truth {
				t.Fatalf("truth=%d, want %d", got, tc.truth)
			}
		})
	}
	if pyTruth(nil, newPyState(), 0) != 0 || pyTruth(item, newPyState(), 33) != 0 {
		t.Fatal("truth limit inferred a value")
	}
	for _, tc := range []struct {
		json  string
		truth uint8
	}{{json: "0", truth: 1}, {json: "42", truth: 2}, {json: "0.0", truth: 1}, {json: "1.5", truth: 2}, {
		json:  "1e999",
		truth: 0,
	}} {
		var node frontend.Node
		raw := `{"type":"Constant","start":0,"end":1,"fields":{"value":` + tc.json + `}}`
		if err := json.Unmarshal([]byte(raw), &node); err != nil {
			t.Fatal(err)
		}
		if got := pyTruth(&node, newPyState(), 0); got != tc.truth {
			t.Fatalf("%s truth=%d", tc.json, got)
		}
	}
}

func TestBranchMergeUpdatesReachableOwnersAndHandlesUnforkedBranches(t *testing.T) {
	for _, mode := range []string{"both", "left-original", "right-original"} {
		global := newPyState()
		local := global.scope()
		a, b := local.fork(), local.fork()
		if mode == "left-original" {
			a = local
		}
		if mode == "right-original" {
			b = local
		}
		if owner := a.forks[global]; owner != nil {
			owner.set("secret", pyValue{origins: []pyOrigin{{kind: "input", start: 1, end: 2}}})
		}
		if owner := b.forks[global]; owner != nil {
			owner.set("secret", pyValue{origins: []pyOrigin{{kind: "environment", start: 3, end: 4}}})
		}
		mergePyBranches(local, a, b)
		value, _ := global.lookup("secret")
		expected := 1
		if mode == "both" {
			expected = 2
		}
		if len(value.origins) != expected || local.parent != global || local.global != global {
			t.Fatalf("%s lost reachable owner effects: %+v", mode, value)
		}
	}
}

func TestImportCallPreservesEvaluatedModuleLiteral(t *testing.T) {
	for _, text := range []string{"os", strings.Repeat("a", 257)} {
		w, s := semanticWalker(t), newPyState()
		call := semanticNode(t, frontend.Call, frontend.ChildField(frontend.Func, semanticName(t, "__import__")), frontend.NodesField(frontend.Args, []*frontend.Node{
			semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue(text))),
		}))
		if value := w.expr(call, s, 0); value.symbol() != text {
			t.Fatal("import value lost the already parsed module literal")
		}
	}
	w := semanticWalker(t)
	empty := semanticNode(t, frontend.Call, frontend.ChildField(frontend.Func, semanticName(t, "__import__")))
	if value := w.expr(empty, newPyState(), 0); value.symbol() != "" {
		t.Fatal("empty import call acquired a value")
	}
}

func TestPrebindInstallsAllLocalTargetShapesBeforeEvaluation(t *testing.T) {
	alias := semanticNode(t, frontend.Alias, frontend.TextField(frontend.FieldName, "package.child"), frontend.TextField(frontend.Asname, "module"))
	tuple := semanticNode(t, frontend.Tuple, frontend.NodesField(frontend.Elts, []*frontend.Node{semanticName(t, "one"), semanticName(t, "two")}))
	statements := []*frontend.Node{
		semanticNode(t, frontend.Assign, frontend.NodesField(frontend.Targets, []*frontend.Node{tuple})),
		semanticNode(t, frontend.AnnAssign, frontend.ChildField(frontend.Target, semanticName(t, "annotated"))),
		semanticNode(t, frontend.For, frontend.ChildField(frontend.Target, semanticName(t, "iteration"))),
		semanticNode(t, frontend.Import, frontend.NodesField(frontend.Names, []*frontend.Node{alias})),
	}
	w, s := semanticWalker(t), newPyState().scope()
	w.prebind(statements, s)
	for _, name := range []string{"one", "two", "annotated", "iteration", "module"} {
		if !s.locals[name] {
			t.Fatalf("local target %q was not prebound", name)
		}
	}
	declarations := []*frontend.Node{semanticNode(t, frontend.Global, frontend.StringsField(frontend.Names, []string{"outer"})), semanticNode(t, frontend.Nonlocal, frontend.StringsField(frontend.Names, []string{"nonlocal_name"}))}
	w.prebind(declarations, s)
	w.block(declarations, s, 0)
	if s.declarations["outer"] != "global" || s.declarations["nonlocal_name"] != "nonlocal" {
		t.Fatal("scope declarations lost")
	}
}

func TestAnnotationOnlyStatementsPreserveExistingValues(t *testing.T) {
	for _, kind := range []string{"name", "attribute", "subscript"} {
		t.Run(kind, func(t *testing.T) {
			w, state := semanticWalker(t), newPyState()
			value := namedValue("exec")
			var target *frontend.Node
			switch kind {
			case "name":
				state.set("run", value)
				target = semanticName(t, "run")
			case "attribute":
				state.set("holder", instanceValue(&pyInstance{fields: map[string]pyValue{"run": value}}))
				target = semanticNode(t, frontend.Attribute,
					frontend.ChildField(frontend.FieldValue, semanticName(t, "holder")), frontend.TextField(frontend.Attr, "run"))
			case "subscript":
				state.set("holder", pyValue{meaning: &pyMapping{entries: map[string]pyValue{"run": value}}})
				target = semanticNode(t, frontend.Subscript,
					frontend.ChildField(frontend.FieldValue, semanticName(t, "holder")),
					frontend.ChildField(frontend.Slice, semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("run")))))
			}
			statement := semanticNode(t, frontend.AnnAssign,
				frontend.ChildField(frontend.Target, target), frontend.ChildField(frontend.Annotation, semanticName(t, "object")))
			w.block([]*frontend.Node{statement}, state, 0)
			if got := w.expr(target, state, 0).symbol(); got != "exec" {
				t.Fatalf("annotation erased the existing callable: %q", got)
			}
		})
	}
}

func TestAnnotationsRetainObservationsWithoutMutatingOuterState(t *testing.T) {
	for _, field := range []frontend.FieldKind{frontend.Posonlyargs, frontend.Args, frontend.KWOnlyargs, frontend.Vararg, frontend.Kwarg, frontend.Returns, frontend.Annotation} {
		t.Run(field.String(), func(t *testing.T) {
			walker, state := semanticWalker(t), newPyState()
			state.set("chosen", literalValue("public", true, 2))
			state.set("run", namedValue("exec"))
			annotation := semanticAssign(t, "chosen", semanticNode(t, frontend.Call,
				frontend.ChildField(frontend.Func, semanticName(t, "eval"))))
			switch field {
			case frontend.Returns:
				walker.definitionAnnotations(nil, annotation, state, 0)
			case frontend.Annotation:
				walker.assignmentStatement(semanticNode(t, frontend.AnnAssign,
					frontend.ChildField(frontend.Target, semanticName(t, "run")),
					frontend.ChildField(frontend.Annotation, annotation)), state, 0)
			default:
				parameter := semanticNode(t, frontend.Arg,
					frontend.TextField(frontend.FieldArg, "value"),
					frontend.ChildField(frontend.Annotation, annotation))
				argumentField := frontend.NodesField(field, []*frontend.Node{parameter})
				if field == frontend.Vararg || field == frontend.Kwarg {
					argumentField = frontend.ChildField(field, parameter)
				}
				walker.definitionAnnotations(semanticNode(t, frontend.Arguments, argumentField), nil, state, 0)
			}
			result, err := walker.facts.result(ruleAST2, 16)
			if err != nil || result.Truncated || len(result.Matches) != 1 {
				t.Fatalf("annotation observation lost: %+v %v", result, err)
			}
			value, _ := state.lookup("chosen")
			text, known := value.literal()
			run, _ := state.lookup("run")
			if !known || text != "public" || run.symbol() != "exec" || walker.err != nil || walker.truncated {
				t.Fatal("isolated annotation changed outer bindings or did not complete")
			}
		})
	}
}

func TestDictionaryProjectionTracksKnownSpreadsAndRejectsUnknownKeys(t *testing.T) {
	w, s := semanticWalker(t), newPyState()
	s.set("spread", pyValue{meaning: &pyMapping{entries: map[string]pyValue{"secret": {origins: []pyOrigin{{
		kind:  "input",
		start: 1,
		end:   2,
	}}}}}})
	dict := semanticNode(t, frontend.Dict, frontend.NodesField(frontend.Keys, []*frontend.Node{nil}), frontend.NodesField(frontend.Values, []*frontend.Node{semanticName(t, "spread")}))
	value := w.expr(dict, s, 0)
	if value.mapping() == nil || len(value.origins) != 1 {
		t.Fatal("known dictionary spread lost content identity or taint")
	}
	dynamic := semanticNode(t, frontend.Dict, frontend.NodesField(frontend.Keys, []*frontend.Node{semanticName(t, "dynamic")}), frontend.NodesField(frontend.Values, []*frontend.Node{semanticName(t, "spread")}))
	value = w.expr(dynamic, s, 0)
	if value.mapping() != nil || !w.limited || len(value.origins) != 1 {
		t.Fatal("unknown key was represented as an exact mapping or lost taint")
	}
}

func TestUnknownStatementRetainsObservationsAndInvalidatesBindings(t *testing.T) {
	w, s := semanticWalker(t), semanticState()
	call := semanticNode(t, frontend.Call, frontend.ChildField(frontend.Func, semanticName(t, "eval")))
	barrier := semanticNode(t, frontend.UnsupportedStatement, frontend.NodesField(frontend.Body, []*frontend.Node{call}))
	w.block([]*frontend.Node{barrier}, s, 0)
	value, _ := s.lookup("left")
	result, err := w.facts.result("AST2", 10)
	if err != nil || len(result.Matches) != 1 {
		t.Fatal("unknown statement dropped a visible independent call")
	}
	if value.meaning != nil || !s.blockedBuiltins || s.resolve("exec") != "" {
		t.Fatal("unknown statement kept speculative definite bindings")
	}
}

func TestDictionaryPreservesKeyOriginsWithoutGuessingTheirValues(t *testing.T) {
	w, state := semanticWalker(t), newPyState()
	state.set("key", pyValue{origins: []pyOrigin{{kind: "environment", start: 1, end: 2}}})
	dictionary := semanticNode(t, frontend.Dict,
		frontend.NodesField(frontend.Keys, []*frontend.Node{semanticName(t, "key")}),
		frontend.NodesField(frontend.Values, []*frontend.Node{semanticNode(t, frontend.Constant, frontend.LiteralField(frontend.StringValue("public")))}))
	value := w.expr(dictionary, state, 0)
	if value.mapping() != nil || !w.limited || len(value.origins) != 1 || value.origins[0].kind != "environment" || value.origins[0].start != 1 {
		t.Fatalf("dynamic dictionary key lost its source or became an exact mapping: %+v", value)
	}
}

func TestWithAliasesBindBeforeBodyAndDeleteClearsTheTarget(t *testing.T) {
	w, s := semanticWalker(t), semanticState()
	item := semanticNode(t, frontend.WithItem, frontend.ChildField(frontend.ContextExpr, semanticName(t, "left")), frontend.ChildField(frontend.OptionalVars, semanticName(t, "stream")))
	with := semanticNode(t, frontend.With, frontend.NodesField(frontend.Items, []*frontend.Node{item}), frontend.NodesField(frontend.Body, []*frontend.Node{
		semanticAssign(t, "held", semanticName(t, "stream")),
	}))
	deletion := semanticNode(t, frontend.Delete, frontend.NodesField(frontend.Targets, []*frontend.Node{semanticName(t, "stream")}))
	w.block([]*frontend.Node{with, deletion}, s, 0)
	held, _ := s.lookup("held")
	stream, _ := s.lookup("stream")
	if text, known := held.literal(); !known || text != "left" {
		t.Fatal("with alias was not visible to its body")
	}
	if stream.meaning != nil || len(stream.origins) != 0 {
		t.Fatal("delete retained the old target value")
	}
}

// These tests exercise the typed interpreter directly. Synthetic IR covers
// control forms whose native grammar projection is intentionally still partial.
func semanticNode(t *testing.T, kind frontend.NodeKind, fields ...frontend.Field) *frontend.Node {
	t.Helper()
	n, err := frontend.NewNode(kind, 0, 1, fields...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func semanticName(t *testing.T, name string) *frontend.Node {
	return semanticNode(t, frontend.Name, frontend.TextField(frontend.ID, name))
}

func semanticAssign(t *testing.T, name string, value *frontend.Node) *frontend.Node {
	return semanticNode(t, frontend.NamedExpr, frontend.ChildField(frontend.Target, semanticName(t, name)), frontend.ChildField(frontend.FieldValue, value))
}

func semanticWalker(t *testing.T) *pyWalker {
	t.Helper()
	return &pyWalker{
		ctx:   context.Background(),
		unit:  pythonFactsUnit(t, "0123456789", source.Span{Start: 0, End: 10}),
		facts: newPythonFacts([]string{"AST1", "AST2", "TT1", "TT2", "TT5"}, 32),
	}
}

func semanticState() *pyState {
	s := newPyState()
	s.set("left", literalValue("left", true, 2))
	s.set("right", literalValue("right", true, 2))
	return s
}

func TestPrebindHonorsTheAnalysisBudgetAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		walker, state := semanticWalker(t), newPyState().scope()
		if canceled {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			walker.ctx = ctx
		} else {
			walker.ctx = analysisbudget.WithLimit(t.Context(), 1)
		}
		assignment := semanticAssign(t, "exec", semanticName(t, "value"))
		walker.prebind([]*frontend.Node{semanticNode(t, frontend.Expr, frontend.ChildField(frontend.FieldValue, assignment))}, state)
		if canceled {
			if !errors.Is(walker.err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", walker.err)
			}
		} else if !walker.truncated {
			t.Fatal("prebinding ignored the operation budget")
		}
		if state.locals["exec"] {
			t.Fatal("prebinding continued after cancellation or exhaustion")
		}
	}
}

func TestLocalDeclarationsShadowBuiltinsBeforeTheirStatement(t *testing.T) {
	name := func() *frontend.Node { return semanticName(t, "exec") }
	star := semanticNode(t, frontend.Starred, frontend.ChildField(frontend.FieldValue, name()))
	for _, node := range []*frontend.Node{
		semanticNode(t, frontend.Assign, frontend.NodesField(frontend.Targets, []*frontend.Node{star})),
		semanticNode(t, frontend.Delete, frontend.NodesField(frontend.Targets, []*frontend.Node{name()})),
		semanticNode(t, frontend.NamedExpr, frontend.ChildField(frontend.Target, name())),
		semanticNode(t, frontend.With, frontend.NodesField(frontend.Items, []*frontend.Node{
			semanticNode(t, frontend.WithItem, frontend.ChildField(frontend.OptionalVars, name())),
		})),
		semanticNode(t, frontend.AsyncWith, frontend.NodesField(frontend.Items, []*frontend.Node{
			semanticNode(t, frontend.WithItem, frontend.ChildField(frontend.OptionalVars, name())),
		})),
	} {
		t.Run(node.Kind().String(), func(t *testing.T) {
			walker, state := semanticWalker(t), newPyState().scope()
			walker.prebind([]*frontend.Node{node}, state)
			if got := state.resolve("exec"); got != "" {
				t.Fatalf("local declaration resolves to builtin %q before execution", got)
			}
		})
	}
}

func TestStarredAssignmentShadowsWithoutInventingUnpackedValue(t *testing.T) {
	walker, state := semanticWalker(t), newPyState()
	target := semanticNode(t, frontend.Starred, frontend.ChildField(frontend.FieldValue, semanticName(t, "exec")))
	walker.assign(target, namedValue("eval"), state, target)
	if got := state.resolve("exec"); got != "" || !walker.limited {
		t.Fatalf("starred assignment resolves to %q, limited=%v", got, walker.limited)
	}
}

func TestNamedExpressionDeclarationsRespectNestedScopes(t *testing.T) {
	assignment := semanticAssign(t, "exec", semanticName(t, "value"))
	defaults := semanticNode(t, frontend.Arguments, frontend.NodesField(frontend.Defaults, []*frontend.Node{assignment}))
	for _, tc := range []struct {
		name  string
		node  *frontend.Node
		local bool
	}{
		{"expression", semanticNode(t, frontend.Expr, frontend.ChildField(frontend.FieldValue, assignment)), true},
		{"lambda body", semanticNode(t, frontend.Lambda, frontend.ChildField(frontend.Body, assignment)), false},
		{"lambda default", semanticNode(t, frontend.Lambda, frontend.ChildField(frontend.Args, defaults)), true},
		{"function body", semanticNode(t, frontend.FunctionDef, frontend.TextField(frontend.FieldName, "inner"), frontend.NodesField(frontend.Body, []*frontend.Node{assignment})), false},
		{"function default", semanticNode(t, frontend.FunctionDef, frontend.TextField(frontend.FieldName, "inner"), frontend.ChildField(frontend.Args, defaults)), true},
		{"class body", semanticNode(t, frontend.ClassDef, frontend.TextField(frontend.FieldName, "Inner"), frontend.NodesField(frontend.Body, []*frontend.Node{assignment})), false},
		{"class base", semanticNode(t, frontend.ClassDef, frontend.TextField(frontend.FieldName, "Inner"), frontend.NodesField(frontend.Bases, []*frontend.Node{assignment})), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			walker, state := semanticWalker(t), newPyState().scope()
			walker.prebind([]*frontend.Node{tc.node}, state)
			want := "exec"
			if tc.local {
				want = ""
			}
			if got := state.resolve("exec"); got != want {
				t.Fatalf("resolved %q, want %q", got, want)
			}
		})
	}
}

func TestRecursiveContentsRespectWorkBudget(t *testing.T) {
	for _, kind := range []string{"mapping", "handler"} {
		for _, mode := range []string{"limited", "complete", "cancelled"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				state := newPyState()
				value := contentsBudgetValue(kind)
				state.set("data", value)
				walk := semanticWalker(t)
				walk.facts.outputs[ruleAST1].Add(check.Match{Start: 1, End: 2})
				limit := uint64(8)
				if mode == "complete" {
					limit = 4096
				}
				walk.ctx = analysisbudget.WithLimit(t.Context(), limit)
				if mode == "cancelled" {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					walk.ctx = &stateCancelContext{Context: ctx, cancel: cancel, remaining: 8}
				}
				var got pyValue
				if kind == "mapping" {
					got = walk.expr(semanticName(t, "data"), state, 0)
				} else {
					got = walk.callResult(pyCall{name: "urllib.request.build_opener", values: []pyValue{value}})
				}
				switch mode {
				case "limited":
					if !walk.truncated || !analysisbudget.Exhausted(walk.ctx) || analysisbudget.Used(walk.ctx) > limit {
						t.Fatal("recursive contents bypassed the quota")
					}
				case "cancelled":
					if !errors.Is(walk.err, context.Canceled) || walk.truncated {
						t.Fatal("recursive contents ignored cancellation")
					}
				case "complete":
					if walk.err != nil || walk.truncated || len(got.origins) != 1 || got.origins[0].kind != "fixture" {
						t.Fatal("admitted refresh lost its content origin")
					}
				}
				if mode != "complete" && (got.meaning != nil || len(got.origins) != 0) {
					t.Fatal("interrupted refresh published a partial value")
				}
				if state.names["data"].meaning != value.meaning {
					t.Fatal("refresh changed the original container")
				}
				walk.facts.finish(walk.err, walk.truncated)
				result, err := walk.facts.result(ruleAST1, 32)
				if len(result.Matches) != 1 || result.Matches[0].Start != 1 || result.Matches[0].End != 2 || result.Truncated != (mode == "limited") || errors.Is(err, context.Canceled) != (mode == "cancelled") {
					t.Fatalf("refresh lost prior facts or completion state: %+v / %v", result, err)
				}
			})
		}
	}
}

func contentsBudgetValue(kind string) pyValue {
	groups := map[string]pyValue{}
	for i := range 4 {
		entries := map[string]pyValue{}
		for j := range 16 {
			entries[strconv.Itoa(j)] = literalValue("ordinary", true, 2)
		}
		entries["marker"] = pyValue{origins: []pyOrigin{{kind: "fixture", start: 3, end: 4}}}
		if kind == "mapping" {
			groups[strconv.Itoa(i)] = pyValue{meaning: &pyMapping{entries: entries}}
		} else {
			groups[strconv.Itoa(i)] = instanceValue(&pyInstance{fields: entries})
		}
	}
	if kind == "mapping" {
		return pyValue{meaning: &pyMapping{entries: groups}}
	}
	return instanceValue(&pyInstance{fields: groups})
}
