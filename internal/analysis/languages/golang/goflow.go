package golang

import (
	"context"
	"go/ast"
	"go/token"
	"maps"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/gobind"
	"github.com/skarm/scout/report"
)

const (
	MaxGoFlowOperations = 20000
	MaxGoFlowBindings   = 1024
)

type goFlow struct{}

type flowValue struct {
	trace []trace
	bound bool
}
type (
	flowState  map[*gobind.Binding]flowValue
	flowWalker struct {
		ctx       context.Context
		unit      document.GoUnit
		imports   goScope
		remaining *int
		out       *result
		budget    int
	}
)

func (goFlow) Rule() report.Rule {
	return report.Rule{
		ID:          ruleGO004,
		Version:     "1",
		Title:       "Credential values may flow through local variables to an HTTP API",
		Description: "A bounded local source/assignment/HTTP-argument chain was found.",
		Severity:    report.High,
		Category:    "credential-egress",
		Method:      "go-ast-local-flow",
		Limitation:  "Intrafunction local variables, selected pure wrappers and conservative if branches only; unknown calls/control flow invalidate tracked bindings. No type checking, cross-file/call graph, general alias analysis or proof of transmission or malicious intent. Legitimate authentication may match.",
	}
}

func (goFlow) AppliesTo(f document.File) bool { return f.HasGo() }

func (a goFlow) Find(ctx context.Context, f document.File, budget int) (result, error) {
	out := result{}
	if err := ctx.Err(); err != nil {
		return out, err
	}

	ops := MaxGoFlowOperations

	for _, unit := range f.GoUnits() {
		if unit.Tree == nil {
			continue
		}

		a := flowWalker{
			ctx:       ctx,
			unit:      unit,
			imports:   importNames(unit.Tree, unit.Bindings),
			remaining: &ops,
			out:       &out,
			budget:    budget,
		}
		a.fileFunctions(unit.Tree.Decls)

		if out.Truncated || ctx.Err() != nil {
			break
		}
	}

	return out, ctx.Err()
}

func (a *flowWalker) fileFunctions(declarations []ast.Decl) {
	for _, declaration := range declarations {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Body != nil {
			a.block(function.Body.List, make(flowState), 0)
		}

		if a.out.Truncated || a.ctx.Err() != nil {
			return
		}
	}
}

func (a *flowWalker) charge(depth int) bool {
	if depth > 32 {
		a.out.Truncated = true
		return false
	}

	*a.remaining--
	if *a.remaining < 0 || !analysisbudget.Consume(a.ctx, 1) {
		a.out.Truncated = true
	}

	return !a.out.Truncated && a.ctx.Err() == nil
}

func (a *flowWalker) trace(v flowValue, node ast.Node, role string) flowValue {
	if len(v.trace) >= 7 {
		a.out.Truncated = true
		return flowValue{}
	}

	span, ok := nodeSpan(a.unit, node)
	if !ok {
		return flowValue{}
	}

	v.trace = append(append([]trace(nil), v.trace...), trace{Role: role, Start: span.Start, End: span.End})

	return v
}

func (a *flowWalker) expr(e ast.Expr, s flowState, depth int) flowValue {
	if e == nil || !a.charge(depth) {
		return flowValue{}
	}

	switch x := e.(type) {
	case *ast.Ident:
		if v, ok := s[a.imports.bindings.Lookup(x)]; ok {
			v.bound = true
			return v
		}
	case *ast.CallExpr:
		return a.callExpr(x, s, depth)
	default:
		operands, preserves := goExpressionOperands(e, a.imports)

		var first flowValue

		for _, operand := range operands {
			value := a.expr(operand, s, depth+1)
			if preserves {
				first = firstFlow(first, value)
			}
		}

		return first
	}

	return flowValue{}
}

func (a *flowWalker) callExpr(x *ast.CallExpr, s flowState, depth int) flowValue {
	if !completeCall(a.unit, x) {
		return flowValue{}
	}

	args := make([]flowValue, len(x.Args))
	for i, e := range x.Args {
		args[i] = a.expr(e, s, depth+1)
	}

	pkg, method := qualified(x.Fun, a.imports)
	if source := goFlowSources[goCallName{pkg: pkg, method: method}]; source != nil && len(x.Args) == 1 {
		text, known := constantString(x.Args[0], a.imports)
		if known && source(text) {
			return a.trace(flowValue{}, x, "source")
		}

		return flowValue{}
	}

	if pkg == "net/http" && a.httpSink(x, method, args) {
		return flowValue{}
	}

	return a.wrapperCall(x, s, args)
}

func (a *flowWalker) httpSink(x *ast.CallExpr, method string, args []flowValue) bool {
	indexes := goHTTPArguments[method]

	for _, i := range indexes {
		if i < len(args) && args[i].bound && len(args[i].trace) > 0 {
			a.sink(x, args[i])
			break
		}
	}

	return len(indexes) > 0
}

func (a *flowWalker) wrapperCall(x *ast.CallExpr, s flowState, args []flowValue) flowValue {
	pure := transparentGoCall(x.Fun, a.imports, false)

	if pure && len(args) == 1 {
		return args[0]
	}
	// Unknown calls may invoke closures or modify aliased data. Never preserve a
	// stale taint chain by guessing that user functions are pure/sanitizers.
	clearState(s)

	return flowValue{}
}

func (a *flowWalker) sink(call *ast.CallExpr, v flowValue) {
	if len(a.out.Matches) >= a.budget {
		a.out.Truncated = true
		return
	}

	span, ok := nodeSpan(a.unit, call)
	if !ok {
		return
	}
	// One result per sink even when multiple arguments carry the same source.
	for _, m := range a.out.Matches {
		if m.Start == span.Start && m.End == span.End {
			return
		}
	}

	if len(v.trace) > 7 {
		a.out.Truncated = true
		return
	}

	tr := append(append([]trace(nil), v.trace...), trace{Role: "sink", Start: span.Start, End: span.End})
	a.out.Matches = append(a.out.Matches, match{Start: span.Start, End: span.End, Trace: tr})
}

func (a *flowWalker) bind(s flowState, id *ast.Ident, v flowValue) {
	if id == nil || id.Name == "_" || a.imports.bindings.Lookup(id) == nil {
		return
	}

	if len(v.trace) == 0 {
		delete(s, a.imports.bindings.Lookup(id))
		return
	}

	if len(s) >= MaxGoFlowBindings {
		a.out.Truncated = true

		clearState(s)

		return
	}

	v = a.trace(v, id, "transform")
	if len(v.trace) > 0 {
		s[a.imports.bindings.Lookup(id)] = v
	}
}

func (a *flowWalker) assign(lhs []ast.Expr, rhs []ast.Expr, tok token.Token, s flowState) {
	vs := a.assignmentValues(rhs, len(lhs), s)

	for i, e := range lhs {
		id, ok := e.(*ast.Ident)
		if !ok {
			clearState(s)
			continue
		}

		v := vs[i]

		if tok == token.ADD_ASSIGN {
			v = firstFlow(s[a.imports.bindings.Lookup(id)], v)
		} else if tok != token.ASSIGN && tok != token.DEFINE {
			v = flowValue{}
		}

		a.bind(s, id, v)
	}
}

func (a *flowWalker) assignmentValues(rhs []ast.Expr, count int, s flowState) []flowValue {
	values := make([]flowValue, len(rhs))
	for i, e := range rhs {
		values[i] = a.expr(e, s, 0)
	}

	if count == len(rhs) {
		return values
	}

	tuple := make([]flowValue, count)
	if count > 0 && len(rhs) == 1 && tupleSource(rhs[0], a.imports) {
		tuple[0] = values[0]
	}

	return tuple
}

// block returns false when execution unconditionally leaves this block.
func (a *flowWalker) block(stmts []ast.Stmt, s flowState, depth int) bool {
	if depth > 32 {
		a.out.Truncated = true
		return false
	}

	for _, st := range stmts {
		if !a.charge(depth) {
			return false
		}

		if !a.statement(st, s, depth) {
			return false
		}
	}

	return true
}

func (a *flowWalker) statement(st ast.Stmt, s flowState, depth int) bool {
	switch x := st.(type) {
	case *ast.ReturnStmt:
		for _, e := range x.Results {
			a.expr(e, s, 0)
		}

		return false
	case *ast.BlockStmt:
		return a.block(x.List, s, depth+1)
	case *ast.IfStmt:
		return a.ifStatement(x, s, depth)
	default:
		a.simpleStatement(st, s)
	}

	return true
}

func (a *flowWalker) simpleStatement(st ast.Stmt, s flowState) {
	switch x := st.(type) {
	case *ast.AssignStmt:
		a.assign(x.Lhs, x.Rhs, x.Tok, s)
	case *ast.ExprStmt:
		a.expr(x.X, s, 0)
	case *ast.DeclStmt:
		a.declaration(x, s)
	case *ast.GoStmt:
		a.expr(x.Call, s, 0)
		clearState(s)
	case *ast.DeferStmt:
		a.expr(x.Call, s, 0)
		clearState(s)
	case *ast.EmptyStmt:
	default:
		clearState(s)
	}
}

func (a *flowWalker) declaration(x *ast.DeclStmt, s flowState) {
	g, ok := x.Decl.(*ast.GenDecl)
	if !ok {
		clearState(s)
		return
	}

	for _, sp := range g.Specs {
		if v, ok := sp.(*ast.ValueSpec); ok {
			left := make([]ast.Expr, len(v.Names))
			for i, id := range v.Names {
				left[i] = id
			}

			a.assign(left, v.Values, token.ASSIGN, s)
		}
	}
}

func (a *flowWalker) ifStatement(x *ast.IfStmt, s flowState, depth int) bool {
	if x.Init != nil {
		a.block([]ast.Stmt{x.Init}, s, depth+1)
	}

	a.expr(x.Cond, s, 0)
	left, right := cloneState(s), cloneState(s)
	lok := a.block(x.Body.List, left, depth+1)

	rok := true
	if x.Else != nil {
		rok = a.block([]ast.Stmt{x.Else}, right, depth+1)
	}

	clearState(s)

	if lok {
		maps.Copy(s, left)
	}

	if rok {
		for k, v := range right {
			if len(s[k].trace) == 0 {
				s[k] = v
			}
		}
	}

	if len(s) > MaxGoFlowBindings {
		a.out.Truncated = true

		clearState(s)

		return false
	}

	return lok || rok
}

func cloneState(s flowState) flowState {
	out := make(flowState, len(s))
	maps.Copy(out, s)

	return out
}
func clearState(s flowState) { clear(s) }
func firstFlow(vs ...flowValue) flowValue {
	for _, v := range vs {
		if len(v.trace) > 0 {
			return v
		}
	}

	return flowValue{}
}

func tupleSource(call ast.Expr, imports goScope) bool {
	c, ok := call.(*ast.CallExpr)
	if !ok {
		return false
	}

	pkg, m := qualified(c.Fun, imports)

	return (pkg == "os" && (m == "LookupEnv" || m == "ReadFile")) || (pkg == "io/ioutil" && m == "ReadFile")
}
