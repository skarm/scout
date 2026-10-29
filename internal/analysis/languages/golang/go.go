package golang

import (
	"context"
	"errors"
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/gobind"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	goShell goKind = iota
	goSensitiveRead
	goDirectHTTP
)

const (
	MaxStaticStringBytes  = literals.MaxStaticStringBytes
	MaxConstantOperations = 256
)

type goKind uint8

type goCheck struct {
	kind  goKind
	facts check.LanguageFacts
}

func (a goCheck) Rule() report.Rule {
	r := report.Rule{
		Version: "1", Method: "go-ast", Severity: report.Medium,
		Limitation: "Go syntax only, not type checking or proof of execution. Resolves literal strings, constant concatenation and selected library calls; mutable-variable flow and cross-file resolution are not supported.",
	}

	switch a.kind {
	case goShell:
		r.ID, r.Title, r.Category = ruleGO001, "Go constructs a shell command", "process-execution"
	case goSensitiveRead:
		r.ID, r.Title, r.Category = ruleGO002, "Go file API references a sensitive credential path", "credential-access"
	case goDirectHTTP:
		r.ID, r.Title, r.Category = ruleGO003, "Credential material flows directly into an HTTP body API", "credential-egress"
		r.Severity, r.Method = report.High, "go-ast-direct-flow"
		r.Limitation += " Direct nested expressions only; legitimate credential exchange can also match. Request construction does not prove transmission or malicious intent."
	}

	r.Description = r.Title

	return r
}

func (goCheck) AppliesTo(f document.File) bool { return f.HasGo() }

func (a goCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	if err := ctx.Err(); err != nil {
		return result{}, err
	}

	if a.facts != nil {
		return a.facts.Result(f, a.Rule().ID, budget)
	}
	// Standalone callers use the same fact collector and completion semantics
	// as selected multi-rule preparation; there is one Go AST traversal model.
	facts := check.NewFileLanguageFacts(map[string]int{a.Rule().ID: budget})
	Collect(ctx, f, facts)

	return facts.Rules[a.Rule().ID].Result(budget)
}

func (a goCheck) WithLanguageFacts(facts check.LanguageFacts) analyzer {
	a.facts = facts
	return a
}

func (a goCheck) matchCall(call *ast.CallExpr, imports goScope) (ast.Expr, bool) {
	pkg, method := qualified(call.Fun, imports)

	index, modeled := goPatternArguments[a.kind][goCallName{pkg: pkg, method: method}]
	if !modeled || len(call.Args) <= index {
		return nil, false
	}

	argument := call.Args[index]
	if a.kind == goDirectHTTP {
		origin := sensitiveExpression(argument, imports, 0)
		return origin, origin != nil
	}

	text, known := constantString(argument, imports)

	return nil, known && goLiteralPredicates[a.kind](text)
}

func appendGoMatch(unit document.GoUnit, call *ast.CallExpr, origin ast.Expr, budget int, result *result, mappingErr *error) bool {
	span, ok := nodeSpan(unit, call)
	if !ok {
		*mappingErr = errors.New("go AST source mapping failed")
		return false
	}

	if len(result.Matches) >= budget {
		result.Truncated = true
		return false
	}

	m := match{Start: span.Start, End: span.End}

	if origin != nil {
		if src, valid := nodeSpan(unit, origin); valid {
			m.Trace = []trace{{Role: "source", Start: src.Start, End: src.End}, {
				Role:  "sink",
				Start: span.Start,
				End:   span.End,
			}}
		} else {
			*mappingErr = errors.New("go AST trace mapping failed")
			return false
		}
	}

	result.Matches = append(result.Matches, m)

	return true
}

func completeCall(unit document.GoUnit, call *ast.CallExpr) bool {
	file := unit.Tokens.File(call.Pos())
	if file == nil || !call.Lparen.IsValid() || !call.Rparen.IsValid() {
		return false
	}

	left, right := int(call.Lparen)-file.Base(), int(call.Rparen)-file.Base()
	text := unit.View.Text()

	return left >= 0 && right > left && right < len(text) && text[left] == '(' && text[right] == ')'
}

func nodeSpan(unit document.GoUnit, n ast.Node) (source.Span, bool) {
	file := unit.Tokens.File(n.Pos())
	if file == nil || n.End() < n.Pos() || n.End() > token.Pos(file.Base()+file.Size()) {
		return source.Span{}, false
	}

	s, err := unit.View.Original(source.Span{Start: file.Offset(n.Pos()), End: file.Offset(n.End())})

	return s, err == nil
}

type goScope struct {
	packages map[string]string
	bindings gobind.Bindings
}

func importNames(f *ast.File, bindings gobind.Bindings) goScope {
	m := make(map[string]string, len(f.Imports))
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}

		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}

		if name != "." && name != "_" {
			m[name] = p
		}
	}

	return goScope{packages: m, bindings: bindings}
}

func qualified(expr ast.Expr, imports goScope) (pkg, name string) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}

	id, ok := selector.X.(*ast.Ident)
	// Lexical bindings distinguish local/package declarations. A shadowed import is not
	// the standard-library package and must not produce a package-API match.
	if !ok || imports.bindings.Lookup(id) != nil {
		return "", ""
	}

	return imports.packages[id.Name], selector.Sel.Name
}

func constantString(e ast.Expr, imports goScope) (string, bool) {
	remaining := MaxConstantOperations
	return evalString(e, imports, 0, &remaining)
}

func evalString(e ast.Expr, imports goScope, depth int, remaining *int) (string, bool) {
	if depth > 16 || *remaining <= 0 {
		return "", false
	}

	*remaining--

	switch x := e.(type) {
	case *ast.BasicLit:
		return constantGoLiteral(x)
	case *ast.ParenExpr:
		return evalString(x.X, imports, depth+1, remaining)
	case *ast.BinaryExpr:
		return constantGoSum(x, imports, depth, remaining)
	case *ast.Ident:
		return constantGoReference(x, imports, depth, remaining)
	case *ast.CallExpr:
		return evalStringCall(x, imports, depth, remaining)
	}

	return "", false
}

// Constant evaluation is a small grammar, with an independent operation bound
// shared by references, concatenations and selected library calls.
func constantGoLiteral(literal *ast.BasicLit) (string, bool) {
	if literal.Kind != token.STRING || len(literal.Value) > 6*MaxStaticStringBytes+2 {
		return "", false
	}

	value, err := strconv.Unquote(literal.Value)

	return value, err == nil && len(value) <= MaxStaticStringBytes
}

func constantGoSum(sum *ast.BinaryExpr, imports goScope, depth int, remaining *int) (string, bool) {
	if sum.Op != token.ADD {
		return "", false
	}

	left, a := evalString(sum.X, imports, depth+1, remaining)

	right, b := evalString(sum.Y, imports, depth+1, remaining)
	if !a || !b || len(left)+len(right) > MaxStaticStringBytes {
		return "", false
	}

	return left + right, true
}

func constantGoReference(reference *ast.Ident, imports goScope, depth int, remaining *int) (string, bool) {
	binding := imports.bindings.Lookup(reference)
	if binding == nil || binding.Constant == nil {
		return "", false
	}

	return evalString(binding.Constant, imports, depth+1, remaining)
}

func evalStringCall(call *ast.CallExpr, imports goScope, depth int, remaining *int) (string, bool) {
	pkg, method := qualified(call.Fun, imports)
	switch (goCallName{pkg: pkg, method: method}) {
	case goCallName{pkg: "os", method: "Getenv"}:
		if len(call.Args) != 1 {
			return "", false
		}

		value, known := evalString(call.Args[0], imports, depth+1, remaining)
		if known && value == "HOME" {
			return "$HOME", true
		} // symbolic, never a host lookup

		return "", false
	case goCallName{pkg: "path", method: "Join"}, goCallName{pkg: "path/filepath", method: "Join"}:
		return constantGoJoin(call.Args, imports, depth, remaining)
	}

	return "", false
}

func constantGoJoin(args []ast.Expr, imports goScope, depth int, remaining *int) (string, bool) {
	if len(args) == 0 || len(args) > 32 {
		return "", false
	}

	parts := make([]string, 0, len(args))
	total := 0

	for _, arg := range args {
		value, known := evalString(arg, imports, depth+1, remaining)
		if !known || strings.ContainsRune(value, '\\') {
			return "", false
		}

		total += len(value)
		if total > MaxStaticStringBytes {
			return "", false
		}

		parts = append(parts, value)
	}

	return path.Join(parts...), true
}

// sensitiveExpression follows only selected direct value-preserving wrappers.
// It does not treat arbitrary function calls as taint propagation and never
// reads environment variables or files. Recursion has an independent ceiling.
func sensitiveExpression(expr ast.Expr, imports goScope, depth int) ast.Expr {
	if depth > 24 {
		return nil
	}

	if call, ok := expr.(*ast.CallExpr); ok {
		return sensitiveCall(call, imports, depth)
	}

	operands, preserves := goExpressionOperands(expr, imports)
	if !preserves {
		return nil
	}

	return sensitiveGoOperands(operands, imports, depth)
}

func sensitiveCall(x *ast.CallExpr, imports goScope, depth int) ast.Expr {
	pkg, method := qualified(x.Fun, imports)
	if pkg == "os" && method == "Getenv" && len(x.Args) == 1 {
		if s, ok := constantString(x.Args[0], imports); ok && literals.SensitiveName(s) {
			return x
		}

		return nil
	}

	if !transparentGoCall(x.Fun, imports, true) {
		return nil
	}

	return sensitiveGoOperands(x.Args, imports, depth)
}

func sensitiveGoOperands(operands []ast.Expr, imports goScope, depth int) ast.Expr {
	for _, operand := range operands {
		if sensitive := sensitiveExpression(operand, imports, depth+1); sensitive != nil {
			return sensitive
		}
	}

	return nil
}
