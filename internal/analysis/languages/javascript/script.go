package javascript

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

type scriptCheck struct {
	id    string
	facts check.LanguageFacts
}

type scriptValue struct {
	name, text     string
	known, dynamic bool
	shell          bool
	stringValue    bool
	primitive      bool // number, boolean, null or undefined; never an object coercion
	valueType      scriptType
	secret         *scriptsyntax.Node
}
type scriptType uint8

const (
	scriptUnknown scriptType = iota
	scriptNonString
	scriptPromiseResponse
	scriptResponse
	scriptPromiseText
)

type scriptScope struct {
	values map[string]scriptValue
	parent *scriptScope
}

const (
	maxScriptOperations = 50000
	maxScriptDepth      = 64
	maxScopeBindings    = 1024
	maxStringBytes      = 16384
)

type scriptWalk struct {
	ctx        context.Context
	unit       document.Unit
	facts      *check.FileLanguageFacts
	operations int
	err        error
	limited    bool
}

func Collect(ctx context.Context, doc document.File, facts *check.FileLanguageFacts) {
	selected := false
	for _, a := range Rules() {
		selected = selected || facts.Rules[a.Rule().ID] != nil
	}

	if !selected {
		return
	}

	w := scriptWalk{ctx: ctx, facts: facts, operations: maxScriptOperations}

	for _, unit := range doc.Units() {
		tree, ok := unit.Tree.(scriptsyntax.Tree)
		if !ok || tree.Root == nil {
			continue
		}

		w.unit = unit
		w.statement(tree.Root, newScriptScope(nil), 0)

		if w.err != nil {
			break
		}
	}

	for _, a := range Rules() {
		if f := facts.Rules[a.Rule().ID]; f != nil {
			f.Finish(errors.Join(w.err, ctx.Err()), w.limited)
		}
	}
}

func (a scriptCheck) Rule() report.Rule {
	title, category := "", ""
	version := "1"

	switch a.id {
	case ruleJS001:
		title, category = "JavaScript constructs a shell command", report.CategoryProcessExecution
		version = "2"
	case ruleJS002:
		title, category = "JavaScript evaluates code dynamically", report.CategoryDynamicExecution
	case ruleJS003:
		title, category = "Credential material reaches a JavaScript network API", report.CategoryCredentialEgress
	case ruleJS004:
		title, category = "Dynamically constructed SQL reaches a JavaScript query API", report.CategorySQLInjection
	case ruleJS005:
		title, category = "JavaScript reads a sensitive credential path", report.CategoryCredentialAccess
	case ruleJS006:
		title, category = "JavaScript disables TLS certificate verification", report.CategoryInsecureTransport
	}

	return report.Rule{
		ID:          a.id,
		Version:     version,
		Title:       title,
		Description: title,
		Severity:    report.High,
		Category:    category,
		Method:      "javascript-typescript-tree-sitter-flow",
		Limitation:  "Bounded JavaScript/TypeScript syntax, lexical import aliases, local assignments and selected API models. No execution, package resolution, general type analysis or cross-file flow. Query methods are syntactic SQL-shaped sinks; legitimate administration/authentication can match. Unsupported syntax and exhausted budgets remain gaps.",
	}
}

func (scriptCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if u.Language == language.JavaScript || u.Language == language.TypeScript {
			return true
		}
	}

	return false
}

func (a scriptCheck) WithLanguageFacts(facts check.LanguageFacts) analyzer { a.facts = facts; return a }

func (a scriptCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	if a.facts != nil {
		return a.facts.Result(f, a.id, budget)
	}

	facts := check.NewFileLanguageFacts(map[string]int{a.id: budget})
	Collect(ctx, f, facts)

	return facts.Rules[a.id].Result(budget)
}

func newScriptScope(parent *scriptScope) *scriptScope {
	return &scriptScope{values: map[string]scriptValue{}, parent: parent}
}

func (s *scriptScope) get(name string) (scriptValue, bool) {
	for p := s; p != nil; p = p.parent {
		if v, ok := p.values[name]; ok {
			return v, true
		}
	}

	return scriptValue{}, false
}

func (s *scriptScope) set(name string, v scriptValue, declare bool) {
	if !declare {
		for p := s; p != nil; p = p.parent {
			if _, ok := p.values[name]; ok {
				p.values[name] = v
				return
			}
		}
	}

	s.values[name] = v
}

func (w *scriptWalk) cloneScope(s *scriptScope) *scriptScope {
	if s == nil || !w.chargeOperations(0, len(s.values)+1) {
		return nil
	}

	parent := w.cloneScope(s.parent)
	if w.err != nil {
		return nil
	}

	out := newScriptScope(parent)
	maps.Copy(out.values, s.values)

	return out
}

func (w *scriptWalk) charge(depth int) bool {
	return w.chargeOperations(depth, 1)
}

func (w *scriptWalk) chargeOperations(depth, units int) bool {
	if w.err != nil {
		return false
	}

	if units < 0 {
		w.err = errors.New("invalid script operation charge")
		return false
	}

	w.operations -= units
	if depth > maxScriptDepth || w.operations < 0 || !analysisbudget.Consume(w.ctx, uint64(units)) {
		w.err = errors.New("script analysis budget exceeded")
	}

	if err := w.ctx.Err(); err != nil {
		w.err = err
	}

	return w.err == nil
}

func (w *scriptWalk) text(n *scriptsyntax.Node) string {
	if n == nil || n.Start < 0 || n.End > len(w.unit.View.Text()) || n.Start > n.End {
		return ""
	}

	value, err := scriptsyntax.IdentifierText(n.Kind, w.unit.View.Text()[n.Start:n.End])
	if err != nil {
		w.err = err
	}

	return value
}

func (w *scriptWalk) emit(id string, n, origin *scriptsyntax.Node, signals ...string) {
	f := w.facts.Rules[id]
	if f == nil || f.Done() || n == nil || n.Invalid {
		return
	}

	span, err := w.unit.View.Original(source.Span{Start: n.Start, End: n.End})
	if err != nil {
		w.err = errors.New("script evidence mapping failed")
		return
	}

	m := match{Start: span.Start, End: span.End, ContextSignals: signals}
	if origin != nil {
		at, err := w.unit.View.Original(source.Span{Start: origin.Start, End: origin.End})
		if err != nil {
			w.err = errors.New("script flow mapping failed")
			return
		}

		m.Trace = []trace{{Role: report.TraceSource, Start: at.Start, End: at.End}, {
			Role:  report.TraceSink,
			Start: span.Start,
			End:   span.End,
		}}
	}

	f.Add(m)
}

func (w *scriptWalk) statement(n *scriptsyntax.Node, s *scriptScope, depth int) bool {
	if n == nil || !w.charge(depth) {
		return false
	}

	switch n.Kind {
	case scriptsyntax.KindProgram, scriptsyntax.KindStatementBlock:
		local := newScriptScope(s)
		w.predeclare(n, local)

		for _, c := range n.Children {
			if !w.statement(c, local, depth+1) {
				return false
			}
		}
	case scriptsyntax.KindImportStatement:
		w.importStatement(n, s)
	case scriptsyntax.KindLexicalDeclaration, scriptsyntax.KindVariableDeclaration:
		for _, c := range n.Children {
			if c.Kind == scriptsyntax.KindVariableDeclarator {
				w.bind(c.Child(scriptsyntax.FieldName), w.expr(c.Child(scriptsyntax.FieldValue), s, depth+1), s, true)
			}
		}
	case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindGeneratorFunctionDeclaration:
		w.function(n, s, depth+1)
	case scriptsyntax.KindReturnStatement, scriptsyntax.KindThrowStatement:
		for _, c := range n.Children {
			w.expr(c, s, depth+1)
		}

		return false
	case scriptsyntax.KindIfStatement:
		w.expr(n.Child(scriptsyntax.FieldCondition), s, depth+1)

		left, right := w.cloneScope(s), w.cloneScope(s)
		if w.err != nil {
			return false
		}

		w.statement(n.Child(scriptsyntax.FieldConsequence), left, depth+1)

		if alt := n.Child(scriptsyntax.FieldAlternative); alt != nil {
			w.statement(alt, right, depth+1)
		}

		w.joinScopes(s, left, right)
	case scriptsyntax.KindExpressionStatement:
		for _, c := range n.Children {
			w.expr(c, s, depth+1)
		}
	case scriptsyntax.KindExportStatement:
		for _, c := range n.Children {
			w.statement(c, s, depth+1)
		}
	default:
		w.expr(n, s, depth+1)
	}

	return true
}

func (w *scriptWalk) predeclare(n *scriptsyntax.Node, s *scriptScope) {
	if !w.chargeOperations(0, len(n.Children)) {
		return
	}

	for _, c := range n.Children {
		switch c.Kind {
		case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindClassDeclaration, scriptsyntax.KindVariableDeclarator:
			w.bind(c.Child(scriptsyntax.FieldName), scriptValue{}, s, true)
		case scriptsyntax.KindLexicalDeclaration, scriptsyntax.KindVariableDeclaration:
			w.predeclare(c, s)
		}

		if w.err != nil {
			return
		}
	}
}

func (w *scriptWalk) function(n *scriptsyntax.Node, s *scriptScope, depth int) {
	local := newScriptScope(w.cloneScope(s))
	if w.err != nil {
		return
	}

	params := n.Child(scriptsyntax.FieldParameters)
	if params != nil && w.chargeOperations(0, len(params.Children)) {
		for _, p := range params.Children {
			w.bind(p, scriptValue{}, local, true)
		}
	}

	w.bind(n.Child(scriptsyntax.FieldParameter), scriptValue{}, local, true)

	body := n.Child(scriptsyntax.FieldBody)
	if body != nil && body.Kind == scriptsyntax.KindStatementBlock {
		w.statement(body, local, depth+1)
	} else {
		w.expr(body, local, depth+1)
	}
}

func (w *scriptWalk) joinScopes(dst, left, right *scriptScope) {
	for dst != nil && left != nil && right != nil {
		if !w.chargeOperations(0, len(dst.values)+1) {
			return
		}

		for k := range dst.values {
			dst.values[k] = joinScriptValues(left.values[k], right.values[k])
		}

		dst, left, right = dst.parent, left.parent, right.parent
	}
}

func joinScriptValues(a, b scriptValue) scriptValue {
	v := scriptValue{secret: a.secret, dynamic: a.dynamic || b.dynamic, shell: a.shell || b.shell, primitive: a.primitive && b.primitive}
	if v.secret == nil {
		v.secret = b.secret
	}

	if a.name == b.name {
		v.name = a.name
	}

	if a.valueType == b.valueType {
		v.valueType = a.valueType
	}

	v.stringValue = a.stringValue && b.stringValue
	if a.known && b.known && a.text == b.text && a.valueType == b.valueType && a.stringValue == b.stringValue {
		v.known = true
		v.text = a.text
	}

	return v
}

func (w *scriptWalk) bind(n *scriptsyntax.Node, v scriptValue, s *scriptScope, declare bool) {
	if n == nil || w.err != nil {
		return
	}

	switch n.Kind {
	case scriptsyntax.KindIdentifier, scriptsyntax.KindShorthandPropertyIdentifierPattern:
		if _, exists := s.values[w.text(n)]; declare && !exists && len(s.values) >= maxScopeBindings {
			w.err = errors.New("script binding limit")
			return
		}

		s.set(w.text(n), v, declare)
	case scriptsyntax.KindObjectPattern:
		if !w.chargeOperations(0, len(n.Children)) {
			return
		}

		for _, c := range n.Children {
			if c.Kind == scriptsyntax.KindShorthandPropertyIdentifierPattern {
				w.bind(c, w.patternProperty(v, c), s, declare)
			}

			if c.Kind == scriptsyntax.KindPairPattern {
				w.bind(c.Child(scriptsyntax.FieldValue), w.patternProperty(v, c.Child(scriptsyntax.FieldKey)), s, declare)
			}

			if c.Kind == scriptsyntax.KindRestPattern || c.Kind == scriptsyntax.KindObjectAssignmentPattern {
				w.shadowPattern(c, s, declare, 0)
			}
		}
	case scriptsyntax.KindArrayPattern:
		w.shadowPattern(n, s, declare, 0)
	case scriptsyntax.KindRequiredParameter, scriptsyntax.KindOptionalParameter, scriptsyntax.KindAssignmentPattern, scriptsyntax.KindRestPattern:
		if !w.chargeOperations(0, len(n.Children)) {
			return
		}

		for _, c := range n.Children {
			if c.Field == scriptsyntax.FieldPattern || c.Field == scriptsyntax.FieldLeft || c.Kind == scriptsyntax.KindIdentifier || c.Kind == scriptsyntax.KindArrayPattern || c.Kind == scriptsyntax.KindObjectPattern {
				w.bind(c, v, s, declare)
				break
			}
		}
	}
}

// Unsupported value projections still introduce local names. Keeping those
// names unknown prevents an accidental fallback to a global API model.
func (w *scriptWalk) shadowPattern(n *scriptsyntax.Node, s *scriptScope, declare bool, depth int) {
	if n == nil || !w.charge(depth) {
		return
	}

	w.limited = true

	switch n.Kind {
	case scriptsyntax.KindIdentifier, scriptsyntax.KindShorthandPropertyIdentifierPattern:
		w.bind(n, scriptValue{}, s, declare)
	case scriptsyntax.KindPairPattern:
		w.shadowPattern(n.Child(scriptsyntax.FieldValue), s, declare, depth+1)
	case scriptsyntax.KindAssignmentPattern, scriptsyntax.KindObjectAssignmentPattern:
		w.shadowPattern(n.Child(scriptsyntax.FieldLeft), s, declare, depth+1)
	case scriptsyntax.KindObjectPattern, scriptsyntax.KindArrayPattern, scriptsyntax.KindRestPattern:
		for _, child := range n.Children {
			w.shadowPattern(child, s, declare, depth+1)
		}
	}
}

func (w *scriptWalk) patternProperty(value scriptValue, key *scriptsyntax.Node) scriptValue {
	name := w.text(key)
	if decoded, ok := scriptLiteral(name); ok {
		name = decoded
	}

	property := scriptValue{name: value.name + "." + name}
	if value.name == "process.env" && literals.SensitiveName(name) {
		property.secret = key
	}

	return property
}

func (w *scriptWalk) importStatement(n *scriptsyntax.Node, s *scriptScope) {
	module, ok := scriptLiteral(w.text(n.Child(scriptsyntax.FieldSource)))
	if !ok {
		return
	}

	module = strings.TrimPrefix(module, "node:")

	var walk func(*scriptsyntax.Node)

	walk = func(n *scriptsyntax.Node) {
		switch n.Kind {
		case scriptsyntax.KindImportSpecifier:
			name := n.Child(scriptsyntax.FieldName)

			alias := n.Child(scriptsyntax.FieldAlias)
			if alias == nil {
				alias = name
			}

			w.bind(alias, scriptValue{name: module + "." + w.text(name)}, s, true)

			return
		case scriptsyntax.KindNamespaceImport:
			for _, c := range n.Children {
				if c.Kind == scriptsyntax.KindIdentifier {
					w.bind(c, scriptValue{name: module}, s, true)
				}
			}

			return
		case scriptsyntax.KindImportClause:
			for _, c := range n.Children {
				if c.Kind == scriptsyntax.KindIdentifier {
					w.bind(c, scriptValue{name: module}, s, true)
				} else {
					walk(c)
				}
			}

			return
		}

		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range n.Children {
		if c.Kind == scriptsyntax.KindImportClause {
			walk(c)
		}
	}
}
