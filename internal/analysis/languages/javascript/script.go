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

	w := scriptWalk{ctx: ctx, facts: facts, operations: 50000}

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

	switch a.id {
	case ruleJS001:
		title, category = "JavaScript constructs a shell command", "process-execution"
	case ruleJS002:
		title, category = "JavaScript evaluates code dynamically", "dynamic-execution"
	case ruleJS003:
		title, category = "Credential material reaches a JavaScript network API", "credential-egress"
	case ruleJS004:
		title, category = "Dynamically constructed SQL reaches a JavaScript query API", "sql-injection"
	case ruleJS005:
		title, category = "JavaScript reads a sensitive credential path", "credential-access"
	case ruleJS006:
		title, category = "JavaScript disables TLS certificate verification", "insecure-transport"
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
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

func cloneScriptScope(s *scriptScope) *scriptScope {
	if s == nil {
		return nil
	}

	out := newScriptScope(cloneScriptScope(s.parent))
	maps.Copy(out.values, s.values)

	return out
}

func (w *scriptWalk) charge(depth int) bool {
	if w.err != nil {
		return false
	}

	w.operations--
	if depth > 64 || w.operations < 0 || !analysisbudget.Consume(w.ctx, 1) {
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

	return w.unit.View.Text()[n.Start:n.End]
}

func (w *scriptWalk) emit(id string, n, origin *scriptsyntax.Node) {
	f := w.facts.Rules[id]
	if f == nil || f.Done() || n == nil || n.Invalid {
		return
	}

	span, err := w.unit.View.Original(source.Span{Start: n.Start, End: n.End})
	if err != nil {
		w.err = errors.New("script evidence mapping failed")
		return
	}

	m := match{Start: span.Start, End: span.End}
	if origin != nil {
		at, err := w.unit.View.Original(source.Span{Start: origin.Start, End: origin.End})
		if err != nil {
			w.err = errors.New("script flow mapping failed")
			return
		}

		m.Trace = []trace{{Role: "source", Start: at.Start, End: at.End}, {
			Role:  "sink",
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
	case "program", "statement_block":
		local := newScriptScope(s)
		w.predeclare(n, local)

		for _, c := range n.Children {
			if !w.statement(c, local, depth+1) {
				return false
			}
		}
	case "import_statement":
		w.importStatement(n, s)
	case "lexical_declaration", "variable_declaration":
		for _, c := range n.Children {
			if c.Kind == "variable_declarator" {
				w.bind(c.Child("name"), w.expr(c.Child("value"), s, depth+1), s, true)
			}
		}
	case "function_declaration", "generator_function_declaration":
		w.function(n, s, depth+1)
	case "return_statement", "throw_statement":
		for _, c := range n.Children {
			w.expr(c, s, depth+1)
		}

		return false
	case "if_statement":
		w.expr(n.Child("condition"), s, depth+1)
		left, right := cloneScriptScope(s), cloneScriptScope(s)
		w.statement(n.Child("consequence"), left, depth+1)

		if alt := n.Child("alternative"); alt != nil {
			w.statement(alt, right, depth+1)
		}

		joinScriptScopes(s, left, right)
	case "expression_statement":
		for _, c := range n.Children {
			w.expr(c, s, depth+1)
		}
	case "export_statement":
		for _, c := range n.Children {
			w.statement(c, s, depth+1)
		}
	default:
		w.expr(n, s, depth+1)
	}

	return true
}

func (w *scriptWalk) predeclare(n *scriptsyntax.Node, s *scriptScope) {
	for _, c := range n.Children {
		if c.Kind == "function_declaration" || c.Kind == "class_declaration" {
			w.bind(c.Child("name"), scriptValue{}, s, true)
		}

		if c.Kind == "lexical_declaration" || c.Kind == "variable_declaration" {
			for _, d := range c.Children {
				if d.Kind == "variable_declarator" {
					w.bind(d.Child("name"), scriptValue{}, s, true)
				}
			}
		}
	}
}

func (w *scriptWalk) function(n *scriptsyntax.Node, s *scriptScope, depth int) {
	local := newScriptScope(cloneScriptScope(s))

	params := n.Child("parameters")
	if params != nil {
		for _, p := range params.Children {
			w.bind(p, scriptValue{}, local, true)
		}
	}

	w.bind(n.Child("parameter"), scriptValue{}, local, true)

	body := n.Child("body")
	if body != nil && body.Kind == "statement_block" {
		w.statement(body, local, depth+1)
	} else {
		w.expr(body, local, depth+1)
	}
}

func joinScriptScopes(dst, left, right *scriptScope) {
	for dst != nil && left != nil && right != nil {
		for k := range dst.values {
			a, b := left.values[k], right.values[k]

			v := scriptValue{secret: a.secret, dynamic: a.dynamic || b.dynamic}
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

			if a.known && b.known && a.text == b.text {
				v.known = true
				v.text = a.text
			}

			dst.values[k] = v
		}

		dst, left, right = dst.parent, left.parent, right.parent
	}
}

func (w *scriptWalk) bind(n *scriptsyntax.Node, v scriptValue, s *scriptScope, declare bool) {
	if n == nil {
		return
	}

	switch n.Kind {
	case "identifier", "shorthand_property_identifier_pattern":
		if _, exists := s.values[w.text(n)]; declare && !exists && len(s.values) >= 1024 {
			w.err = errors.New("script binding limit")
			return
		}

		s.set(w.text(n), v, declare)
	case "object_pattern":
		for _, c := range n.Children {
			if c.Kind == "shorthand_property_identifier_pattern" {
				property := scriptValue{name: v.name + "." + w.text(c)}
				if v.name == "process.env" && literals.SensitiveName(w.text(c)) {
					property.secret = c
				}

				w.bind(c, property, s, declare)
			}

			if c.Kind == "pair_pattern" {
				w.bind(c.Child("value"), scriptValue{name: v.name + "." + w.text(c.Child("key"))}, s, declare)
			}
		}
	case "required_parameter", "optional_parameter", "assignment_pattern", "rest_pattern":
		for _, c := range n.Children {
			if c.Field == "pattern" || c.Field == "left" || c.Kind == "identifier" {
				w.bind(c, v, s, declare)
				break
			}
		}
	}
}

func (w *scriptWalk) importStatement(n *scriptsyntax.Node, s *scriptScope) {
	module, ok := scriptLiteral(w.text(n.Child("source")))
	if !ok {
		return
	}

	module = strings.TrimPrefix(module, "node:")

	var walk func(*scriptsyntax.Node)

	walk = func(n *scriptsyntax.Node) {
		switch n.Kind {
		case "import_specifier":
			name := n.Child("name")

			alias := n.Child("alias")
			if alias == nil {
				alias = name
			}

			w.bind(alias, scriptValue{name: module + "." + w.text(name)}, s, true)

			return
		case "namespace_import":
			for _, c := range n.Children {
				if c.Kind == "identifier" {
					w.bind(c, scriptValue{name: module}, s, true)
				}
			}

			return
		case "import_clause":
			for _, c := range n.Children {
				if c.Kind == "identifier" {
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
		if c.Kind == "import_clause" {
			walk(c)
		}
	}
}
