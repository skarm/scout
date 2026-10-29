package golang

import (
	"context"
	"go/ast"
	"go/token"
	"maps"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/gobind"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
	"github.com/skarm/scout/report"
)

type (
	goDatabaseCheck struct{}
	goTLSCheck      struct{}
	goQueryValue    struct {
		text    string
		dynamic bool
	}
)

type goQueryBindings map[*gobind.Binding]goQueryValue

type goQueryWalk struct {
	ctx        context.Context
	unit       document.GoUnit
	imports    goScope
	values     goQueryBindings
	remaining  *int
	out        *result
	mappingErr *error
	budget     int
}

func (goDatabaseCheck) Rule() report.Rule {
	return report.Rule{
		ID:          ruleGO005,
		Version:     "1",
		Title:       "Dynamically constructed SQL reaches a Go query API",
		Description: "SQL-shaped concatenation or formatting is passed to a query method.",
		Severity:    report.High,
		Category:    "sql-injection",
		Method:      "go-ast-query-construction",
		Limitation:  "Bounded same-function assignments and SQL-shaped Query/Exec/Prepare calls, including Context variants. No type checking, cross-file flow, driver semantics or proof of attacker control. Parameters passed separately from a constant query are not interpolation.",
	}
}

func (goDatabaseCheck) AppliesTo(f document.File) bool { return f.HasGo() }

func (goDatabaseCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	var (
		out        result
		mappingErr error
	)

	remaining := MaxGoFlowOperations

	for _, unit := range f.GoUnits() {
		if unit.Tree == nil {
			continue
		}

		walk := goQueryWalk{
			ctx:        ctx,
			unit:       unit,
			imports:    importNames(unit.Tree, unit.Bindings),
			values:     goQueryBindings{},
			remaining:  &remaining,
			out:        &out,
			mappingErr: &mappingErr,
			budget:     budget,
		}
		ast.Inspect(unit.Tree, walk.visit)
	}

	if mappingErr != nil {
		return out, mappingErr
	}

	return out, ctx.Err()
}

func (goTLSCheck) Rule() report.Rule {
	return report.Rule{
		ID:          ruleGO006,
		Version:     "1",
		Title:       "Go TLS configuration disables certificate verification",
		Description: "A crypto/tls.Config literal explicitly enables InsecureSkipVerify.",
		Severity:    report.High,
		Category:    "insecure-transport",
		Method:      "go-ast-tls-configuration",
		Limitation:  "Resolved crypto/tls import and literal true in a Config composite only. Custom certificate callbacks may enforce an alternative trust policy; runtime activation is not established.",
	}
}

func (goTLSCheck) AppliesTo(f document.File) bool { return f.HasGo() }

func (goTLSCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	var out result

	for _, unit := range f.GoUnits() {
		if unit.Tree == nil {
			continue
		}

		imports := importNames(unit.Tree, unit.Bindings)
		ast.Inspect(unit.Tree, func(n ast.Node) bool {
			if n == nil || out.Truncated || ctx.Err() != nil {
				return false
			}

			if !analysisbudget.Consume(ctx, 1) {
				out.Truncated = true
				return false
			}

			literal, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}

			for _, field := range insecureTLSFields(literal, imports) {
				span, ok := nodeSpan(unit, field)
				if !ok {
					continue
				}

				if len(out.Matches) >= budget {
					out.Truncated = true
					return false
				}

				out.Matches = append(out.Matches, match{Start: span.Start, End: span.End})
			}

			return true
		})
	}

	return out, ctx.Err()
}

func insecureTLSFields(literal *ast.CompositeLit, imports goScope) []ast.Node {
	pkg, name := qualified(literal.Type, imports)
	if pkg != "crypto/tls" || name != "Config" {
		return nil
	}

	var fields []ast.Node

	for _, e := range literal.Elts {
		pair, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}

		key, k := pair.Key.(*ast.Ident)

		value, v := pair.Value.(*ast.Ident)
		if k && v && key.Name == "InsecureSkipVerify" && value.Name == "true" && imports.bindings.Lookup(value) == nil {
			fields = append(fields, pair)
		}
	}

	return fields
}

func (w *goQueryWalk) visit(n ast.Node) bool {
	if n == nil || w.out.Truncated || w.ctx.Err() != nil {
		return false
	}

	*w.remaining--
	if *w.remaining < 0 || !analysisbudget.Consume(w.ctx, 1) {
		w.out.Truncated = true
		return false
	}

	switch x := n.(type) {
	case *ast.FuncDecl:
		local := *w

		local.values = goQueryBindings{}
		if x.Body != nil {
			ast.Inspect(x.Body, local.visit)
		}

		return false
	case *ast.FuncLit:
		local := *w
		local.values = maps.Clone(w.values)
		ast.Inspect(x.Body, local.visit)

		return false
	case *ast.AssignStmt:
		w.assign(x)
	case *ast.ValueSpec:
		for i, id := range x.Names {
			if w.imports.bindings.Lookup(id) != nil && i < len(x.Values) {
				w.values[w.imports.bindings.Lookup(id)] = goQueryExpression(x.Values[i], w.imports, w.values, 0)
			}
		}
	case *ast.CallExpr:
		return w.call(x)
	}

	return true
}

func (w *goQueryWalk) assign(x *ast.AssignStmt) {
	next := make([]goQueryValue, len(x.Rhs))
	for i, e := range x.Rhs {
		next[i] = goQueryExpression(e, w.imports, w.values, 0)
	}

	for i, e := range x.Lhs {
		id, ok := e.(*ast.Ident)
		if !ok || w.imports.bindings.Lookup(id) == nil {
			continue
		}

		prior := w.values[w.imports.bindings.Lookup(id)]
		delete(w.values, w.imports.bindings.Lookup(id))

		if i < len(next) {
			value := next[i]
			if x.Tok == token.ADD_ASSIGN && len(prior.text)+len(value.text) <= MaxStaticStringBytes {
				value.text = prior.text + value.text
				value.dynamic = value.dynamic || prior.dynamic
			}

			w.values[w.imports.bindings.Lookup(id)] = value
		}
	}
}

func (w *goQueryWalk) call(x *ast.CallExpr) bool {
	index := goQueryArgument(x)
	if index < 0 || index >= len(x.Args) || !completeCall(w.unit, x) {
		return true
	}

	value := goQueryExpression(x.Args[index], w.imports, w.values, 0)
	if value.dynamic && sqlsyntax.QueryPrefix(value.text) {
		return appendGoMatch(w.unit, x, nil, w.budget, w.out, w.mappingErr)
	}

	return true
}

func goQueryArgument(call *ast.CallExpr) int {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return -1
	}

	name := selector.Sel.Name
	index := 0

	if before, ok0 := strings.CutSuffix(name, "Context"); ok0 {
		name = before
		index = 1
	}

	switch name {
	case "Query", "QueryRow", "Exec", "Prepare":
		return index
	}

	return -1
}

func goQueryExpression(e ast.Expr, imports goScope, values goQueryBindings, depth int) goQueryValue {
	if e == nil || depth > 32 {
		return goQueryValue{}
	}

	if text, ok := constantString(e, imports); ok {
		return goQueryValue{text: text}
	}

	switch x := e.(type) {
	case *ast.Ident:
		if v, ok := values[imports.bindings.Lookup(x)]; ok {
			return v
		}

		return goQueryValue{dynamic: true}
	case *ast.ParenExpr:
		return goQueryExpression(x.X, imports, values, depth+1)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return goQueryValue{}
		}

		a, b := goQueryExpression(x.X, imports, values, depth+1), goQueryExpression(x.Y, imports, values, depth+1)
		if len(a.text)+len(b.text) > MaxStaticStringBytes {
			return goQueryValue{}
		}

		return goQueryValue{text: a.text + b.text, dynamic: a.dynamic || b.dynamic}
	case *ast.CallExpr:
		pkg, method := qualified(x.Fun, imports)
		if pkg == "fmt" && (method == "Sprintf" || method == "Sprint") && len(x.Args) > 0 {
			v := goQueryExpression(x.Args[0], imports, values, depth+1)
			for _, arg := range x.Args[1:] {
				if _, literal := arg.(*ast.BasicLit); !literal {
					v.dynamic = true
				}
			}

			return v
		}
	}

	return goQueryValue{dynamic: true}
}
