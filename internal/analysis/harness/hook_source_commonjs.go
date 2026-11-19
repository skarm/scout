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
	scope        *nodeHookBindings
}

type nodeHookValueKind uint8

const (
	nodeHookUnknown nodeHookValueKind = iota
	nodeHookText
	nodeHookPath
	nodeHookModuleValue
	nodeHookFunction
)

type nodeHookBindings map[string]*nodeHookValue

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

	value, _ := scriptsyntax.IdentifierText(n.Kind, m.unit.View.Text()[n.Start:n.End])

	return value
}

func (m nodeHookModule) namedMember(n *scriptsyntax.Node, object, property string) bool {
	return nodeHookKind(n, scriptsyntax.KindMemberExpression) && len(n.Children) == 3 && n.Children[1].Kind == scriptsyntax.KindDot &&
		nodeHookKind(n.Children[0], scriptsyntax.KindIdentifier) && m.text(n.Children[0]) == object &&
		nodeHookKind(n.Children[2], scriptsyntax.KindPropertyIdentifier) && m.text(n.Children[2]) == property
}

func nodeHookChildren(n *scriptsyntax.Node) []*scriptsyntax.Node {
	if n == nil {
		return nil
	}

	var children []*scriptsyntax.Node

	for _, child := range n.Children {
		switch child.Kind {
		case scriptsyntax.KindOpenParen, scriptsyntax.KindCloseParen, scriptsyntax.KindOpenBracket, scriptsyntax.KindCloseBracket, scriptsyntax.KindOpenBrace, scriptsyntax.KindCloseBrace, scriptsyntax.KindComma, scriptsyntax.KindSemicolon, scriptsyntax.KindComment, scriptsyntax.KindHashBangLine, scriptsyntax.KindReturn:
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

	bindings, ok := w.cloneBindings(bindings)
	if !ok || !w.predeclare(m, block, bindings) {
		return
	}

	for _, n := range nodeHookChildren(block) {
		if !w.plugin.b.step() {
			return
		}

		w.inspectNode(m, n, bindings, steps, depth)

		switch n.Kind {
		case scriptsyntax.KindLexicalDeclaration:
			w.declare(m, n, bindings, depth)
		case scriptsyntax.KindReturnStatement, scriptsyntax.KindThrowStatement, scriptsyntax.KindWithStatement, scriptsyntax.KindVariableDeclaration:
			return
		}
	}
}

func (w *nodeHookWalk) predeclare(m nodeHookModule, block *scriptsyntax.Node, bindings nodeHookBindings) bool {
	locals := make(nodeHookBindings)
	scope := &bindings

	for _, n := range nodeHookChildren(block) {
		if !w.plugin.b.step() {
			return false
		}

		switch n.Kind {
		case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindClassDeclaration:
			name := m.text(n.Child(scriptsyntax.FieldName))
			locals.bind(name, nodeHookValue{})

			if n.Kind == scriptsyntax.KindFunctionDeclaration {
				locals.bind(name, nodeHookValue{kind: nodeHookFunction, fn: n, scope: scope})
			}
		case scriptsyntax.KindLexicalDeclaration, scriptsyntax.KindVariableDeclaration:
			for _, declaration := range n.Children {
				if nodeHookKind(declaration, scriptsyntax.KindVariableDeclarator) {
					w.bindPattern(m, declaration.Child(scriptsyntax.FieldName), nodeHookValue{}, locals)
				}
			}
		}
	}

	if !w.plugin.b.spend(len(locals)) {
		return false
	}

	maps.Copy(bindings, locals)

	return true
}

func (w *nodeHookWalk) declare(m nodeHookModule, declaration *scriptsyntax.Node, bindings nodeHookBindings, depth int) {
	if m.text(declaration.Child(scriptsyntax.FieldKind)) != "const" {
		return
	}

	for _, n := range declaration.Children {
		if nodeHookKind(n, scriptsyntax.KindVariableDeclarator) {
			value := w.value(m, n.Child(scriptsyntax.FieldValue), bindings, depth+1)
			w.bindPattern(m, n.Child(scriptsyntax.FieldName), value, bindings)
		}
	}
}

func (w *nodeHookWalk) bindPattern(m nodeHookModule, pattern *scriptsyntax.Node, value nodeHookValue, bindings nodeHookBindings) {
	if pattern == nil || pattern.Invalid || !w.plugin.b.step() {
		return
	}

	switch pattern.Kind {
	case scriptsyntax.KindIdentifier:
		bindings.bind(m.text(pattern), value)
	case scriptsyntax.KindShorthandPropertyIdentifierPattern:
		name := m.text(pattern)
		if value.kind == nodeHookModuleValue {
			value.export = name
		} else {
			value = nodeHookValue{}
		}

		bindings.bind(name, value)
	case scriptsyntax.KindObjectPattern:
		for _, child := range pattern.Children {
			w.bindPattern(m, child, value, bindings)
		}
	case scriptsyntax.KindPairPattern:
		w.bindPattern(m, pattern.Child(scriptsyntax.FieldValue), nodeHookValue{}, bindings)
	case scriptsyntax.KindAssignmentPattern, scriptsyntax.KindObjectAssignmentPattern:
		// Defaults reference values; only their left side declares names.
		w.bindPattern(m, pattern.Child(scriptsyntax.FieldLeft), nodeHookValue{}, bindings)
	case scriptsyntax.KindRestPattern, scriptsyntax.KindArrayPattern:
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
	case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindFunctionExpression, scriptsyntax.KindArrowFunction, scriptsyntax.KindGeneratorFunction, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindMethodDefinition, scriptsyntax.KindClassDeclaration, scriptsyntax.KindWithStatement:
		return
	case scriptsyntax.KindStatementBlock:
		w.inspectBlock(m, n, bindings, steps, depth)
		return
	case scriptsyntax.KindCatchClause:
		child, ok := w.cloneBindings(bindings)
		if !ok {
			return
		}

		w.bindPattern(m, n.Child(scriptsyntax.FieldParameter), nodeHookValue{}, child)
		w.inspectBlock(m, n.Child(scriptsyntax.FieldBody), child, steps, depth)

		return
	case scriptsyntax.KindIfStatement:
		condition := nodeHookOnly(n.Child(scriptsyntax.FieldCondition))
		w.inspectConditional(m, n, condition, bindings, steps, depth)

		return
	case scriptsyntax.KindTernaryExpression:
		w.inspectConditional(m, n, n.Child(scriptsyntax.FieldCondition), bindings, steps, depth)

		return
	case scriptsyntax.KindBinaryExpression:
		w.inspectBinary(m, n, bindings, steps, depth)

		return
	case scriptsyntax.KindAssignmentExpression, scriptsyntax.KindAugmentedAssignmentExpression:
		w.inspectNode(m, n.Child(scriptsyntax.FieldRight), bindings, steps, depth)

		if left := n.Child(scriptsyntax.FieldLeft); nodeHookKind(left, scriptsyntax.KindIdentifier) {
			bindings.invalidate(m.text(left))
		}

		return
	case scriptsyntax.KindUpdateExpression:
		if argument := n.Child(scriptsyntax.FieldArgument); nodeHookKind(argument, scriptsyntax.KindIdentifier) {
			bindings.invalidate(m.text(argument))
		}

		return
	case scriptsyntax.KindCallExpression:
		w.inspectCall(m, n, bindings, steps, depth)
		return
	}

	for _, child := range n.Children {
		w.inspectNode(m, child, bindings, steps, depth)
	}
}

func (w *nodeHookWalk) inspectConditional(m nodeHookModule, n, condition *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	w.inspectNode(m, condition, bindings, steps, depth)

	consequence, alternative := n.Child(scriptsyntax.FieldConsequence), n.Child(scriptsyntax.FieldAlternative)

	if truth, known := w.truth(m, condition, bindings, depth); known {
		branch := alternative
		if truth {
			branch = consequence
		}

		w.inspectNode(m, branch, bindings, steps, depth)

		return
	}

	left, leftCells := w.forkBindings(bindings)
	if w.plugin.b.stopped {
		return
	}

	right, rightCells := w.forkBindings(bindings)
	if w.plugin.b.stopped {
		return
	}

	w.inspectNode(m, consequence, left, steps, depth)
	w.inspectNode(m, alternative, right, steps, depth)

	w.mergeCells(leftCells, rightCells)
}

func (w *nodeHookWalk) inspectBinary(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	left := n.Child(scriptsyntax.FieldLeft)
	w.inspectNode(m, left, bindings, steps, depth)

	switch op := m.text(n.Child(scriptsyntax.FieldOperator)); op {
	case scriptsyntax.OpAnd, scriptsyntax.OpOr:
		truth, known := w.truth(m, left, bindings, depth)
		if known && truth == (op == scriptsyntax.OpOr) {
			return
		}
	case scriptsyntax.OpNullish:
		if _, known := w.truth(m, left, bindings, depth); known && !nodeHookKind(left, scriptsyntax.KindNull) {
			return
		}
	}

	w.inspectNode(m, n.Child(scriptsyntax.FieldRight), bindings, steps, depth)
}

func (w *nodeHookWalk) truth(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) (bool, bool) {
	if n == nil || depth >= maxHookSourceDepth {
		return false, false
	}

	switch n.Kind {
	case scriptsyntax.KindTrue:
		return true, true
	case scriptsyntax.KindFalse, scriptsyntax.KindNull:
		return false, true
	case scriptsyntax.KindUnaryExpression:
		if m.text(n.Child(scriptsyntax.FieldOperator)) == "!" {
			truth, known := w.truth(m, n.Child(scriptsyntax.FieldArgument), bindings, depth+1)
			return !truth, known
		}
	case scriptsyntax.KindIdentifier:
		value := bindings.value(m.text(n))
		if value.kind == nodeHookText || value.kind == nodeHookPath {
			return value.text != "", true
		}
	}

	return false, false
}

func (w *nodeHookWalk) inspectCall(m nodeHookModule, call *scriptsyntax.Node, bindings nodeHookBindings, steps []report.SourceRef, depth int) {
	fn := call.Child(scriptsyntax.FieldFunction)
	if fn == nil || depth >= maxHookSourceDepth-1 {
		return
	}

	w.inspectNode(m, fn, bindings, steps, depth)

	callee := bindings.value(m.text(fn))
	if fn.Kind == scriptsyntax.KindMemberExpression && nodeHookKind(fn.Child(scriptsyntax.FieldObject), scriptsyntax.KindIdentifier) {
		callee = bindings.value(m.text(fn.Child(scriptsyntax.FieldObject)))
		if callee.kind == nodeHookModuleValue && callee.export == "" {
			callee.export = m.text(fn.Child(scriptsyntax.FieldProperty))
		} else {
			callee = nodeHookValue{}
		}
	}

	// JavaScript captures the callee before evaluating arguments, then runs the
	// body. Keep each argument's value before a later argument can rebind it.
	var args []nodeHookValue

	for _, arg := range nodeHookChildren(call.Child(scriptsyntax.FieldArguments)) {
		w.inspectNode(m, arg, bindings, steps, depth)
		args = append(args, w.value(m, arg, bindings, depth+1))
	}

	switch callee.kind {
	case nodeHookFunction:
		w.inspectFunction(m, callee.fn, args, callee.scope, steps, depth)
	case nodeHookModuleValue:
		w.inspectExport(m, call, callee, steps, depth)
	}
}

func (w *nodeHookWalk) inspectFunction(m nodeHookModule, fn *scriptsyntax.Node, args []nodeHookValue, scope *nodeHookBindings, steps []report.SourceRef, depth int) {
	if fn == nil || !nodeHookStableScope(m, fn.Child(scriptsyntax.FieldBody)) {
		return
	}

	key := nodeHookCall{path: m.rel, at: fn.Start}
	if w.active[key] {
		return
	}

	w.active[key] = true
	defer delete(w.active, key)

	child, ok := w.cloneBindings(*scope)
	if !ok {
		return
	}

	for i, param := range nodeHookChildren(fn.Child(scriptsyntax.FieldParameters)) {
		value := nodeHookValue{}
		if i < len(args) {
			value = args[i]
		}

		w.bindPattern(m, param, value, child)
	}

	w.inspectBlock(m, fn.Child(scriptsyntax.FieldBody), child, steps, depth+1)
}

func nodeHookStableScope(m nodeHookModule, n *scriptsyntax.Node) bool {
	if n == nil || n.Invalid {
		return false
	}

	switch n.Kind {
	case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindFunctionExpression, scriptsyntax.KindArrowFunction, scriptsyntax.KindGeneratorFunction, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindMethodDefinition:
		return true
	case scriptsyntax.KindWithStatement, scriptsyntax.KindVariableDeclaration, scriptsyntax.KindImportStatement:
		return false
	case scriptsyntax.KindAssignmentExpression, scriptsyntax.KindAugmentedAssignmentExpression, scriptsyntax.KindUpdateExpression:
		left := n.Child(scriptsyntax.FieldLeft)
		if n.Kind == scriptsyntax.KindUpdateExpression {
			left = n.Child(scriptsyntax.FieldArgument)
		}

		if !nodeHookKind(left, scriptsyntax.KindIdentifier) {
			return false
		}

		switch m.text(left) {
		case "require", "module", "process", "__dirname":
			return false
		}
	case scriptsyntax.KindUnaryExpression:
		if m.text(n.Child(scriptsyntax.FieldOperator)) == "delete" {
			return false
		}
	case scriptsyntax.KindCallExpression:
		if m.text(n.Child(scriptsyntax.FieldFunction)) == "eval" {
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
	if fn == nil || w.active[nodeHookCall{path: target.rel, at: fn.Start}] || !nodeHookStableScope(target, fn.Child(scriptsyntax.FieldBody)) {
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
		Steps: steps, Scope: scope, Exclude: nodeHookNestedFunctions(target, fn.Child(scriptsyntax.FieldBody)),
	})

	w.inspectFunction(target, fn, nil, &bindings, steps, depth)
}

func nodeHookNestedFunctions(m nodeHookModule, root *scriptsyntax.Node) []source.Span {
	var spans []source.Span

	var visit func(*scriptsyntax.Node)

	visit = func(n *scriptsyntax.Node) {
		switch n.Kind {
		case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindFunctionExpression, scriptsyntax.KindArrowFunction, scriptsyntax.KindGeneratorFunction, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindMethodDefinition:
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
	if !w.predeclare(m, m.root, bindings) {
		return nil, nil
	}

	var exported *scriptsyntax.Node

	statements := nodeHookChildren(m.root)
	for i, statement := range statements {
		if !w.plugin.b.step() {
			return nil, nil
		}

		switch statement.Kind {
		case scriptsyntax.KindLexicalDeclaration:
			w.declare(m, statement, bindings, depth)
		case scriptsyntax.KindFunctionDeclaration:
		case scriptsyntax.KindExpressionStatement:
			expr := nodeHookOnly(statement)
			if nodeHookKind(expr, scriptsyntax.KindString) {
				continue
			}

			if !nodeHookKind(expr, scriptsyntax.KindAssignmentExpression) || !m.namedMember(expr.Child(scriptsyntax.FieldLeft), "module", "exports") {
				return nil, nil
			}

			object := expr.Child(scriptsyntax.FieldRight)
			if i != len(statements)-1 || !nodeHookKind(object, scriptsyntax.KindObject) {
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
		if member.Kind != scriptsyntax.KindShorthandPropertyIdentifier {
			return nil, nil
		}

		if m.text(member) == name {
			if found != nil {
				return nil, nil
			}

			value := bindings.value(name)
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
