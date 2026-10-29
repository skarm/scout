//nolint:testpackage // Tests exercise the resolver's exact private node and depth limits.
package gobind

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestLexicalIdentities(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []int
	}{
		{
			name:   "short-declaration-right-hand-side",
			source: `package p; const x="outer"; func f(){ _=x; { x:=x; _=x }; _=x }`,
			want:   []int{1, 1, 2, 1, 2, 1},
		},
		{
			name:   "parameter-reused-by-short-declaration",
			source: `package p; func f(x int){ x,y:=x,1; _=x; _=y }`,
			want:   []int{1, 1, 1, 1},
		},
		{
			name:   "closure-capture-and-parameter-shadow",
			source: `package p; func f(){ x:=1; func(x int){ _=x }(x); func(){ _=x }() }`,
			want:   []int{1, 2, 2, 1, 1},
		},
		{
			name:   "if-init-and-sibling-scopes",
			source: `package p; func f(){ x:=0; if x:=x; x>0 { x:=x; _=x } else { _=x }; _=x }`,
			want:   []int{1, 2, 1, 2, 3, 2, 3, 2, 1},
		},
		{
			name:   "range-expression-before-new-variable",
			source: `package p; func f(){ x:=[]int{1}; for x:=range x { _=x }; _=x }`,
			want:   []int{1, 2, 1, 2, 1},
		},
		{
			name:   "range-assignment-reuses-variable",
			source: `package p; func f(){ x:=0; for x=range []int{1} { _=x }; _=x }`,
			want:   []int{1, 1, 1, 1},
		},
		{
			name:   "for-init-scope",
			source: `package p; func f(){ x:=1; for x:=x; x<3; x++ { _=x }; _=x }`,
			want:   []int{1, 2, 1, 2, 2, 2, 1},
		},
		{
			name:   "switch-case-scopes",
			source: `package p; func f(){ x:=0; switch { case true: x:=1; _=x; case false: x:=2; _=x }; _=x }`,
			want:   []int{1, 2, 2, 3, 3, 1},
		},
		{
			name:   "type-switch-case-variables",
			source: `package p; func f(x any){ switch x:=x.(type) { case int: _=x; case string: _=x }; _=x }`,
			want:   []int{1, 0, 1, 2, 3, 1},
		},
		{
			name:   "select-case-scopes",
			source: `package p; func f(){ x:=0; select { case x:=<-ch: _=x; case <-ch: _=x }; _=x }`,
			want:   []int{1, 2, 2, 1, 1},
		},
		{
			name:   "imports-and-shadowed-alias",
			source: `package p; import x "os"; func f(){ x.Getenv("A"); { x:=value; _=x }; x.Getenv("B") }`,
			want:   []int{0, 0, 1, 1, 0},
		},
		{
			name:   "generic-type-and-function-parameters",
			source: `package p; type T[x any] struct{ value x }; func f[x any](value x){ _=value }; var _ x`,
			want:   []int{1, 1, 2, 2, 0},
		},
		{
			name:   "generic-receiver-parameters",
			source: `package p; type T[x any] struct{}; func (t T[x]) f(){ var value x; _=value }`,
			want:   []int{1, 2, 2},
		},
		{
			name:   "fields-and-selectors-are-not-local-references",
			source: `package p; var x=1; type S struct{ x int }; func f(s S){ _=s.x }`,
			want:   []int{1, 0, 0},
		},
		{
			name:   "labels-are-not-value-bindings",
			source: `package p; func f(){ x: for { break x } }`,
			want:   []int{0, 0},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := parseSyntax(t, tc.source)
			bindings, err := Resolve(t.Context(), file)
			if err != nil {
				t.Fatal(err)
			}
			groups := make(map[*Binding]int)
			var got []int
			ast.Inspect(file, func(node ast.Node) bool {
				if id, ok := node.(*ast.Ident); ok && id.Name == "x" {
					binding := bindings.Lookup(id)
					group := 0
					if binding != nil {
						if groups[binding] == 0 {
							groups[binding] = len(groups) + 1
						}
						group = groups[binding]
					}
					got = append(got, group)
				}
				return true
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("lexical identities %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConstantInitializersAndForwardReferences(t *testing.T) {
	file := parseSyntax(t, `package p; const next=first; const first="sh"; func f(){ const first="bash"; _=first }; var _=next`)
	bindings, err := Resolve(t.Context(), file)
	if err != nil {
		t.Fatal(err)
	}
	var first []*Binding
	ast.Inspect(file, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == "first" {
			first = append(first, bindings.Lookup(id))
		}
		return true
	})
	if len(first) != 4 || first[0] == nil || first[0] != first[1] || first[2] == nil || first[2] != first[3] || first[0] == first[2] {
		t.Fatal("constant declaration identity was not preserved")
	}
	for i, want := range []string{`"sh"`, `"bash"`} {
		literal, ok := first[i*2].Constant.(*ast.BasicLit)
		if !ok || literal.Value != want {
			t.Fatalf("constant initializer %d: %+v", i, first[i*2].Constant)
		}
	}
}

func TestBindingLimitsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	file := parseSyntax(t, "package p; var x=1")
	if _, err := Resolve(ctx, file); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled binding pass: %v", err)
	}
	if _, err := Resolve(nil, file); err == nil {
		t.Fatal("nil context accepted")
	}
	var expression ast.Expr = ast.NewIdent("x")
	for range maxDepth + 1 {
		expression = &ast.ParenExpr{X: expression}
	}
	deep := &ast.File{Decls: []ast.Decl{&ast.GenDecl{Tok: token.VAR, Specs: []ast.Spec{&ast.ValueSpec{Names: []*ast.Ident{ast.NewIdent("x")}, Values: []ast.Expr{expression}}}}}}
	if _, err := Resolve(t.Context(), deep); !errors.Is(err, ErrLimit) {
		t.Fatalf("unbounded depth accepted: %v", err)
	}
	statements := make([]ast.Stmt, maxNodes+1)
	for i := range statements {
		statements[i] = &ast.EmptyStmt{}
	}
	wide := &ast.File{Decls: []ast.Decl{&ast.FuncDecl{Name: ast.NewIdent("f"), Type: &ast.FuncType{}, Body: &ast.BlockStmt{List: statements}}}}
	if _, err := Resolve(t.Context(), wide); !errors.Is(err, ErrLimit) {
		t.Fatalf("unbounded node count accepted: %v", err)
	}
}

func parseSyntax(t *testing.T, text string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "", text, parser.AllErrors|parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
