package harness

import (
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

type nodeHookModule struct {
	*entry
	rel  string
	unit document.Unit
	root *scriptsyntax.Node
}

type nodeHookValue struct {
	text, export string
	kind         nodeHookValueKind
	fn           *scriptsyntax.Node
	scope        nodeHookBindings
}

type nodeHookValueKind uint8

const (
	nodeHookUnknown nodeHookValueKind = iota
	nodeHookText
	nodeHookPath
	nodeHookModuleValue
	nodeHookFunction
)

type nodeHookBindings map[string]nodeHookValue

type nodeHookWalk struct {
	*hookSourceWalk
	active   map[nodeHookCall]bool
	firstArg hookSourceArgument
}

type nodeHookCall struct {
	path string
	at   int
}

func (w *hookSourceWalk) traceCommonJSHook(target *entry, rel string, firstArg hookSourceArgument, steps []report.SourceRef) {
	m, ok := nodeHookScript(target, rel)
	if !ok || !nodeHookStableScope(m, m.root) {
		return
	}

	walk := nodeHookWalk{hookSourceWalk: w, active: make(map[nodeHookCall]bool), firstArg: firstArg}
	walk.inspectBlock(m, m.root, make(nodeHookBindings), steps, 0)
}

func nodeHookScript(e *entry, rel string) (nodeHookModule, bool) {
	if e == nil || e.doc == nil || (path.Ext(rel) != ".js" && path.Ext(rel) != ".cjs") {
		return nodeHookModule{}, false
	}

	for _, unit := range e.doc.Units() {
		tree, ok := unit.Tree.(scriptsyntax.Tree)
		if ok && tree.Root != nil && unit.Language == language.JavaScript && unit.Origin == "file" {
			return nodeHookModule{entry: e, rel: rel, unit: unit, root: tree.Root}, true
		}
	}

	return nodeHookModule{}, false
}

func (m nodeHookModule) text(n *scriptsyntax.Node) string {
	if n == nil || n.Invalid || n.Start >= n.End || n.End > len(m.unit.View.Text()) {
		return ""
	}

	return m.unit.View.Text()[n.Start:n.End]
}

func nodeHookChildren(n *scriptsyntax.Node) []*scriptsyntax.Node {
	if n == nil {
		return nil
	}

	var children []*scriptsyntax.Node

	for _, child := range n.Children {
		switch child.Kind {
		case "(", ")", "[", "]", "{", "}", ",", ";", "comment", "hash_bang_line", "return":
		default:
			children = append(children, child)
		}
	}

	return children
}

func nodeHookOnly(n *scriptsyntax.Node) *scriptsyntax.Node {
	children := nodeHookChildren(n)
	if len(children) != 1 {
		return nil
	}

	return children[0]
}

func nodeHookKind(n *scriptsyntax.Node, kind string) bool {
	return n != nil && !n.Invalid && n.Kind == kind
}

func (w *nodeHookWalk) inspectBlock(m nodeHookModule, block *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	if block == nil || depth >= maxHookSourceDepth || len(steps) >= maxHookSourceDepth {
		return
	}

	parent := bindings
	bindings = maps.Clone(parent)
	locals := w.predeclare(m, block, bindings)

	defer func() {
		for name := range parent {
			if _, shadowed := locals[name]; !shadowed && bindings[name].kind == nodeHookUnknown {
				parent[name] = nodeHookValue{}
			}
		}
	}()

	for _, n := range nodeHookChildren(block) {
		if !w.plugin.b.step() {
			return
		}

		w.inspectNode(m, n, bindings, steps, depth)

		switch n.Kind {
		case "lexical_declaration":
			w.declare(m, n, bindings, depth)
		case "return_statement", "throw_statement", "with_statement", "variable_declaration":
			return
		}
	}
}

func (w *nodeHookWalk) predeclare(m nodeHookModule, block *scriptsyntax.Node, bindings nodeHookBindings) nodeHookBindings {
	locals := make(nodeHookBindings)

	for _, n := range nodeHookChildren(block) {
		switch n.Kind {
		case "function_declaration", "generator_function_declaration", "class_declaration":
			name := m.text(n.Child("name"))
			locals[name] = nodeHookValue{}

			if n.Kind == "function_declaration" {
				locals[name] = nodeHookValue{kind: nodeHookFunction, fn: n, scope: bindings}
			}
		case "lexical_declaration", "variable_declaration":
			for _, declaration := range n.Children {
				if nodeHookKind(declaration, "variable_declarator") {
					w.bindPattern(m, declaration.Child("name"), nodeHookValue{}, locals)
				}
			}
		}
	}

	maps.Copy(bindings, locals)

	return locals
}

func (w *nodeHookWalk) declare(m nodeHookModule, declaration *scriptsyntax.Node, bindings nodeHookBindings, depth int) {
	if m.text(declaration.Child("kind")) != "const" {
		return
	}

	for _, n := range declaration.Children {
		if nodeHookKind(n, "variable_declarator") {
			value := w.value(m, n.Child("value"), bindings, depth+1)
			w.bindPattern(m, n.Child("name"), value, bindings)
		}
	}
}

func (w *nodeHookWalk) bindPattern(m nodeHookModule, pattern *scriptsyntax.Node, value nodeHookValue, bindings nodeHookBindings) {
	if pattern == nil || pattern.Invalid {
		return
	}

	switch pattern.Kind {
	case "identifier":
		bindings[m.text(pattern)] = value
	case "shorthand_property_identifier_pattern":
		name := m.text(pattern)
		if value.kind == nodeHookModuleValue {
			value.export = name
		} else {
			value = nodeHookValue{}
		}

		bindings[name] = value
	case "object_pattern":
		for _, child := range pattern.Children {
			w.bindPattern(m, child, value, bindings)
		}
	case "pair_pattern":
		w.bindPattern(m, pattern.Child("value"), nodeHookValue{}, bindings)
	case "rest_pattern", "assignment_pattern", "array_pattern":
		for _, child := range pattern.Children {
			w.bindPattern(m, child, nodeHookValue{}, bindings)
		}
	}
}

func (w *nodeHookWalk) inspectNode(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	if n == nil || n.Invalid || !w.plugin.b.step() {
		return
	}

	switch n.Kind {
	case "function_declaration", "function_expression", "arrow_function", "generator_function", "generator_function_declaration", "method_definition", "class_declaration", "with_statement":
		return
	case "statement_block":
		w.inspectBlock(m, n, bindings, steps, depth)
		return
	case "catch_clause":
		child := maps.Clone(bindings)
		w.bindPattern(m, n.Child("parameter"), nodeHookValue{}, child)
		w.inspectBlock(m, n.Child("body"), child, steps, depth)

		return
	case "if_statement":
		condition := nodeHookOnly(n.Child("condition"))
		w.inspectConditional(m, n, condition, bindings, steps, depth)

		return
	case "ternary_expression":
		w.inspectConditional(m, n, n.Child("condition"), bindings, steps, depth)

		return
	case "binary_expression":
		w.inspectBinary(m, n, bindings, steps, depth)

		return
	case "assignment_expression", "augmented_assignment_expression":
		w.inspectNode(m, n.Child("right"), bindings, steps, depth)

		if left := n.Child("left"); nodeHookKind(left, "identifier") {
			bindings[m.text(left)] = nodeHookValue{}
		}

		return
	case "call_expression":
		w.inspectCall(m, n, bindings, steps, depth)
	}

	for _, child := range n.Children {
		w.inspectNode(m, child, bindings, steps, depth)
	}
}

func (w *nodeHookWalk) inspectConditional(m nodeHookModule, n, condition *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	w.inspectNode(m, condition, bindings, steps, depth)

	consequence, alternative := n.Child("consequence"), n.Child("alternative")

	if truth, known := w.truth(m, condition, bindings, depth); known {
		branch := alternative
		if truth {
			branch = consequence
		}

		w.inspectNode(m, branch, bindings, steps, depth)

		return
	}

	left, right := maps.Clone(bindings), maps.Clone(bindings)
	w.inspectNode(m, consequence, left, steps, depth)
	w.inspectNode(m, alternative, right, steps, depth)

	for name := range bindings {
		if left[name].kind == nodeHookUnknown || right[name].kind == nodeHookUnknown {
			bindings[name] = nodeHookValue{}
		}
	}
}

func (w *nodeHookWalk) inspectBinary(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	left := n.Child("left")
	w.inspectNode(m, left, bindings, steps, depth)

	switch op := m.text(n.Child("operator")); op {
	case "&&", "||":
		truth, known := w.truth(m, left, bindings, depth)
		if known && truth == (op == "||") {
			return
		}
	case "??":
		if _, known := w.truth(m, left, bindings, depth); known && !nodeHookKind(left, "null") {
			return
		}
	}

	w.inspectNode(m, n.Child("right"), bindings, steps, depth)
}

func (w *nodeHookWalk) truth(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) (bool, bool) {
	if n == nil || depth >= maxHookSourceDepth {
		return false, false
	}

	switch n.Kind {
	case "true":
		return true, true
	case "false", "null":
		return false, true
	case "unary_expression":
		if m.text(n.Child("operator")) == "!" {
			truth, known := w.truth(m, n.Child("argument"), bindings, depth+1)
			return !truth, known
		}
	case "identifier":
		value := bindings[m.text(n)]
		if value.kind == nodeHookText || value.kind == nodeHookPath {
			return value.text != "", true
		}
	}

	return false, false
}

func (w *nodeHookWalk) inspectCall(m nodeHookModule, call *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	fn := call.Child("function")
	if fn == nil || depth >= maxHookSourceDepth-1 {
		return
	}

	callee := bindings[m.text(fn)]
	if fn.Kind == "member_expression" && nodeHookKind(fn.Child("object"), "identifier") {
		callee = bindings[m.text(fn.Child("object"))]
		if callee.kind == nodeHookModuleValue && callee.export == "" {
			callee.export = m.text(fn.Child("property"))
		} else {
			return
		}
	}

	switch callee.kind {
	case nodeHookFunction:
		args := nodeHookChildren(call.Child("arguments"))
		w.inspectFunction(m, callee.fn, args, bindings, callee.scope, steps, depth)
	case nodeHookModuleValue:
		w.inspectExport(m, call, callee, steps, depth)
	}
}

func (w *nodeHookWalk) inspectFunction(m nodeHookModule, fn *scriptsyntax.Node, args []*scriptsyntax.Node, bindings, scope nodeHookBindings, steps []report.SourceRef, depth int) {
	if fn == nil || !nodeHookStableScope(m, fn.Child("body")) {
		return
	}

	key := nodeHookCall{path: m.rel, at: fn.Start}
	if w.active[key] {
		return
	}

	w.active[key] = true
	defer delete(w.active, key)

	child := maps.Clone(scope)

	for i, param := range nodeHookChildren(fn.Child("parameters")) {
		value := nodeHookValue{}
		if i < len(args) {
			value = w.value(m, args[i], bindings, depth+1)
		}

		w.bindPattern(m, param, value, child)
	}

	w.inspectBlock(m, fn.Child("body"), child, steps, depth+1)
}

func nodeHookStableScope(m nodeHookModule, n *scriptsyntax.Node) bool {
	if n == nil || n.Invalid {
		return false
	}

	switch n.Kind {
	case "function_declaration", "function_expression", "arrow_function", "generator_function", "generator_function_declaration", "method_definition":
		return true
	case "with_statement", "variable_declaration", "import_statement":
		return false
	case "assignment_expression", "augmented_assignment_expression":
		left := n.Child("left")
		if !nodeHookKind(left, "identifier") {
			return false
		}

		switch m.text(left) {
		case "require", "module", "process", "__dirname":
			return false
		}
	case "call_expression":
		if m.text(n.Child("function")) == "eval" {
			return false
		}
	}

	return !slices.ContainsFunc(n.Children, func(child *scriptsyntax.Node) bool { return !nodeHookStableScope(m, child) })
}

func (w *nodeHookWalk) inspectExport(from nodeHookModule, call *scriptsyntax.Node, callee nodeHookValue, steps []report.SourceRef, depth int) {
	if callee.export == "" || len(steps) >= maxHookSourceDepth || len(w.plugin.b.hookSourcePaths) >= w.plugin.b.r.Limits.References {
		return
	}

	target, ok := w.localModule(callee.text)
	if !ok {
		return
	}

	bindings, fn := w.moduleExports(target, callee.export, depth)
	if fn == nil || w.active[nodeHookCall{path: target.rel, at: fn.Start}] || !nodeHookStableScope(target, fn.Child("body")) {
		return
	}

	at, ok := nodeHookLocation(from, call)
	if !ok {
		return
	}

	scope, err := target.unit.View.Original(source.Span{Start: fn.Start, End: fn.End})
	if err != nil {
		return
	}

	steps = append(slices.Clone(steps), at)
	w.plugin.b.hookSourcePaths = append(w.plugin.b.hookSourcePaths, HookSourcePath{
		Target: target.meta.Path, Event: w.event, Language: language.JavaScript,
		Steps: steps, Scope: scope, Exclude: nodeHookNestedFunctions(target, fn.Child("body")),
	})

	w.inspectFunction(target, fn, nil, bindings, bindings, steps, depth)
}

func nodeHookNestedFunctions(m nodeHookModule, root *scriptsyntax.Node) []source.Span {
	var spans []source.Span

	var visit func(*scriptsyntax.Node)

	visit = func(n *scriptsyntax.Node) {
		switch n.Kind {
		case "function_declaration", "function_expression", "arrow_function", "generator_function", "generator_function_declaration", "method_definition":
			if span, err := m.unit.View.Original(source.Span{Start: n.Start, End: n.End}); err == nil {
				spans = append(spans, span)
			}
		default:
			for _, child := range n.Children {
				visit(child)
			}
		}
	}

	if root != nil {
		visit(root)
	}

	return spans
}

func nodeHookLocation(m nodeHookModule, n *scriptsyntax.Node) (report.SourceRef, bool) {
	span, err := m.unit.View.Original(source.Span{Start: n.Start, End: n.End})
	if err != nil {
		return report.SourceRef{}, false
	}

	if at := ref(m.entry, span); at != nil {
		return *at, true
	}

	return report.SourceRef{}, false
}

func (w *nodeHookWalk) moduleExports(m nodeHookModule, name string, depth int) (nodeHookBindings, *scriptsyntax.Node) {
	bindings := make(nodeHookBindings)
	w.predeclare(m, m.root, bindings)

	var exported *scriptsyntax.Node

	statements := nodeHookChildren(m.root)
	for i, statement := range statements {
		if !w.plugin.b.step() {
			return nil, nil
		}

		switch statement.Kind {
		case "lexical_declaration":
			w.declare(m, statement, bindings, depth)
		case "function_declaration":
		case "expression_statement":
			expr := nodeHookOnly(statement)
			if nodeHookKind(expr, "string") {
				continue
			}

			if !nodeHookKind(expr, "assignment_expression") || m.text(expr.Child("left")) != "module.exports" {
				return nil, nil
			}

			object := expr.Child("right")
			if i != len(statements)-1 || !nodeHookKind(object, "object") {
				return nil, nil
			}

			exported = object
		default:
			return nil, nil
		}
	}

	if _, shadowed := bindings["module"]; shadowed || exported == nil {
		return nil, nil
	}

	var found *scriptsyntax.Node

	for _, member := range nodeHookChildren(exported) {
		if member.Kind != "shorthand_property_identifier" {
			return nil, nil
		}

		if m.text(member) == name {
			if found != nil {
				return nil, nil
			}

			value := bindings[name]
			if value.kind == nodeHookFunction {
				found = value.fn
			}
		}
	}

	return bindings, found
}

func (w *nodeHookWalk) localModule(filename string) (nodeHookModule, bool) {
	rel, rooted := strings.CutPrefix(filename, "/")
	if !rooted || rel == "" || path.Clean(rel) != rel {
		return nodeHookModule{}, false
	}

	entry := w.plugin.entry(rel)
	if entry == nil && path.Ext(rel) == "" {
		rel += ".js"
		entry = w.plugin.entry(rel)
	}

	return nodeHookScript(entry, rel)
}
