package golang

import (
	"go/ast"
	"go/token"

	"github.com/skarm/scout/internal/analysis/languages/literals"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var goPatternArguments = map[goKind]map[goCallName]int{
	goShell: {{pkg: "os/exec", method: "Command"}: 0, {pkg: "os/exec", method: "CommandContext"}: 1},
	goSensitiveRead: {
		{pkg: "os", method: "ReadFile"}: 0,
		{pkg: "os", method: "Open"}:     0,
		{
			pkg:    "os",
			method: "OpenFile",
		}: 0,
		{
			pkg:    "io/ioutil",
			method: "ReadFile",
		}: 0,
	},
	goDirectHTTP: {
		{pkg: "net/http", method: "Post"}:       2,
		{pkg: "net/http", method: "NewRequest"}: 2,
		{
			pkg:    "net/http",
			method: "NewRequestWithContext",
		}: 3,
		{
			pkg:    "net/http",
			method: "PostForm",
		}: 1,
	},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	goLiteralPredicates = map[goKind]func(string) bool{
		goShell:         literals.IsShell,
		goSensitiveRead: literals.SensitivePath,
	}
	goTransparentCalls = map[goCallName]bool{
		{pkg: "strings", method: "NewReader"}: true, {pkg: "bytes", method: "NewReader"}: true,
		{pkg: "bytes", method: "NewBuffer"}: true, {pkg: "bytes", method: "NewBufferString"}: true, {
			pkg:    "io",
			method: "NopCloser",
		}: true,
	}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var goHTTPArguments = map[string][]int{
	"Get":                   {0},
	"Head":                  {0},
	"Post":                  {0, 2},
	"PostForm":              {0, 1},
	"NewRequest":            {1, 2},
	"NewRequestWithContext": {2, 3},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var goFlowSources = map[goCallName]func(string) bool{
	{pkg: "os", method: "Getenv"}:          literals.SensitiveName,
	{pkg: "os", method: "LookupEnv"}:       literals.SensitiveName,
	{pkg: "os", method: "ReadFile"}:        literals.SensitivePath,
	{pkg: "io/ioutil", method: "ReadFile"}: literals.SensitivePath,
}

// Library signatures describe the argument carrying each observation. These are
// syntactic models only: the scanner never imports packages or resolves methods.
type goCallName struct{ pkg, method string }

// The two flow analyses share conversions and byte-preserving wrappers. Only
// direct expression analysis additionally treats fmt formatting as transparent.
func transparentGoCall(fun ast.Expr, imports goScope, formatting bool) bool {
	pkg, method := qualified(fun, imports)
	if goTransparentCalls[goCallName{pkg: pkg, method: method}] {
		return true
	}

	if formatting && pkg == "fmt" {
		return method == "Sprint" || method == "Sprintf" || method == "Sprintln"
	}

	return builtinGoConversion(fun, imports)
}

func builtinGoConversion(fun ast.Expr, imports goScope) bool {
	switch x := fun.(type) {
	case *ast.Ident:
		return imports.bindings.Lookup(x) == nil && x.Name == "string"
	case *ast.ArrayType:
		id, ok := x.Elt.(*ast.Ident)
		return x.Len == nil && ok && imports.bindings.Lookup(id) == nil && id.Name == "byte"
	}

	return false
}

// These expressions can hide calls and mutations, but do not preserve a value
// in the supported local-flow grammar. Their operand order remains explicit.
func goUntrackedOperands(e ast.Expr) []ast.Expr {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return []ast.Expr{x.X}
	case *ast.IndexExpr:
		return []ast.Expr{x.X, x.Index}
	case *ast.SliceExpr:
		return []ast.Expr{x.X, x.Low, x.High, x.Max}
	case *ast.TypeAssertExpr:
		return []ast.Expr{x.X}
	case *ast.UnaryExpr:
		return []ast.Expr{x.X}
	}

	return nil
}

func goCompositeOperands(literal *ast.CompositeLit, imports goScope) ([]ast.Expr, bool) {
	pkg, name := qualified(literal.Type, imports)
	valid := literal.Type == nil || (pkg == "net/url" && name == "Values")

	operands := make([]ast.Expr, len(literal.Elts))
	for i, element := range literal.Elts {
		if pair, ok := element.(*ast.KeyValueExpr); ok {
			element = pair.Value
		}

		operands[i] = element
	}

	return operands, valid
}

// Both Go analyses share which syntax preserves a value. Local flow still
// evaluates untracked operands for side effects; direct flow follows only the
// preserving alternatives and never guesses through unrelated expressions.
func goExpressionOperands(expression ast.Expr, imports goScope) ([]ast.Expr, bool) {
	switch x := expression.(type) {
	case *ast.ParenExpr:
		return []ast.Expr{x.X}, true
	case *ast.BinaryExpr:
		return []ast.Expr{x.X, x.Y}, x.Op == token.ADD
	case *ast.CompositeLit:
		return goCompositeOperands(x, imports)
	default:
		return goUntrackedOperands(expression), false
	}
}
