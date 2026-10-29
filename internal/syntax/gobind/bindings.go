// Package gobind associates Go identifiers with lexical declarations without
// type checking, resolving imports, or using the deprecated parser object graph.
package gobind

import (
	"context"
	"errors"
	"go/ast"
	"go/token"
)

const (
	maxNodes = 131072
	maxDepth = 256
)

// ErrLimit means the bounded lexical pass could not finish.
var ErrLimit = errors.New("go lexical binding limit")

// Binding identifies one declaration. Constant retains only an explicitly
// paired constant initializer; an absent initializer is never guessed.
type Binding struct{ Constant ast.Expr }

// Bindings is immutable after Resolve completes. Unresolved names, imports,
// predeclared identifiers, selector members and blank identifiers have no binding.
type Bindings struct{ identifiers map[*ast.Ident]*Binding }

func (b Bindings) Lookup(id *ast.Ident) *Binding { return b.identifiers[id] }

type scope struct {
	parent *scope
	names  map[string]*Binding
}

func nested(parent *scope) *scope { return &scope{parent: parent, names: make(map[string]*Binding)} }

func (s *scope) lookup(name string) *Binding {
	for current := s; current != nil; current = current.parent {
		if binding := current.names[name]; binding != nil {
			return binding
		}
	}

	return nil
}

type resolver struct {
	ctx      context.Context
	bindings Bindings
	nodes    int
	err      error
}

// Resolve handles a single captured Go file, including a usable partial AST.
// It never opens a file or resolves a package beyond the supplied syntax tree.
func Resolve(ctx context.Context, file *ast.File) (Bindings, error) {
	if ctx == nil {
		return Bindings{}, errors.New("nil Go binding context")
	}

	r := resolver{ctx: ctx, bindings: Bindings{identifiers: make(map[*ast.Ident]*Binding)}}
	root := nested(nil)

	if file != nil {
		// Package declarations are visible throughout the file, including before
		// their declaration. Imports deliberately remain outside this value map.
		for _, declaration := range file.Decls {
			r.predeclare(declaration, root)

			if r.err != nil {
				break
			}
		}

		r.walk(file, root, 0)
	}

	if r.err != nil {
		return Bindings{}, r.err
	}

	return r.bindings, ctx.Err()
}

func (r *resolver) admit(depth int) bool {
	if r.err == nil {
		r.err = r.ctx.Err()
	}

	r.nodes++

	if r.err == nil && (depth > maxDepth || r.nodes > maxNodes) {
		r.err = ErrLimit
	}

	return r.err == nil
}

func (r *resolver) declare(s *scope, id *ast.Ident, constant ast.Expr) {
	if id == nil || id.Name == "_" || !r.admit(0) {
		return
	}

	binding := s.names[id.Name]
	if binding == nil {
		binding = &Binding{Constant: constant}
		s.names[id.Name] = binding
	}

	r.bindings.identifiers[id] = binding
}

func (r *resolver) reference(s *scope, id *ast.Ident) {
	if id != nil && id.Name != "_" {
		if binding := s.lookup(id.Name); binding != nil {
			r.bindings.identifiers[id] = binding
		}
	}
}

func (r *resolver) walk(node ast.Node, s *scope, depth int) {
	if node == nil || !r.admit(depth) {
		return
	}

	switch n := node.(type) {
	case *ast.File:
		for _, declaration := range n.Decls {
			r.walk(declaration, s, depth+1)
		}
	case *ast.Ident:
		r.reference(s, n)
	case *ast.SelectorExpr:
		r.walk(n.X, s, depth+1)
	case *ast.ImportSpec, *ast.BranchStmt:
		// Neither import names nor labels are value bindings.
	case *ast.LabeledStmt:
		r.walk(n.Stmt, s, depth+1)
	case *ast.GenDecl:
		r.declaration(n, s, depth+1)
	case *ast.FuncDecl:
		r.function(n.Type, n.Recv, n.Body, s, depth+1)
	case *ast.FuncLit:
		r.function(n.Type, nil, n.Body, s, depth+1)
	case *ast.FuncType:
		r.function(n, nil, nil, s, depth+1)
	case *ast.Field:
		r.walk(n.Type, s, depth+1)
	case *ast.BlockStmt, *ast.AssignStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause:
		r.statement(node, s, depth+1)
	default:
		// Dispatch direct children back through the scope-aware walker.
		root := true

		ast.Inspect(node, func(child ast.Node) bool {
			if root {
				root = false
				return true
			}

			if child != nil {
				r.walk(child, s, depth+1)
			}

			return false
		})
	}
}

func (r *resolver) statement(node ast.Node, s *scope, depth int) {
	switch n := node.(type) {
	case *ast.BlockStmt:
		if n != nil {
			r.statements(n.List, nested(s), depth+1)
		}
	case *ast.AssignStmt:
		r.assignment(n, s, depth+1)
	case *ast.IfStmt:
		inner := nested(s)
		r.walk(n.Init, inner, depth+1)
		r.walk(n.Cond, inner, depth+1)
		r.walk(n.Body, inner, depth+1)
		r.walk(n.Else, inner, depth+1)
	case *ast.ForStmt:
		inner := nested(s)
		r.walk(n.Init, inner, depth+1)
		r.walk(n.Cond, inner, depth+1)
		r.walk(n.Post, inner, depth+1)
		r.walk(n.Body, inner, depth+1)
	case *ast.RangeStmt:
		r.rangeStatement(n, s, depth+1)
	case *ast.SwitchStmt:
		inner := nested(s)
		r.walk(n.Init, inner, depth+1)
		r.walk(n.Tag, inner, depth+1)
		r.walk(n.Body, inner, depth+1)
	case *ast.TypeSwitchStmt:
		r.typeSwitch(n, s, depth+1)
	case *ast.CaseClause:
		inner := nested(s)
		for _, expression := range n.List {
			r.walk(expression, s, depth+1)
		}

		r.statements(n.Body, inner, depth+1)
	case *ast.CommClause:
		inner := nested(s)
		r.walk(n.Comm, inner, depth+1)
		r.statements(n.Body, inner, depth+1)
	}
}

func (r *resolver) statements(statements []ast.Stmt, s *scope, depth int) {
	for _, statement := range statements {
		r.walk(statement, s, depth)

		if r.err != nil {
			return
		}
	}
}

func (r *resolver) assignment(n *ast.AssignStmt, s *scope, depth int) {
	// Short declarations become visible only after all right-hand expressions.
	for _, expression := range n.Rhs {
		r.walk(expression, s, depth)
	}

	for _, expression := range n.Lhs {
		if id, ok := expression.(*ast.Ident); ok && n.Tok == token.DEFINE {
			r.declare(s, id, nil)
		} else {
			r.walk(expression, s, depth)
		}
	}
}

func (r *resolver) rangeStatement(n *ast.RangeStmt, s *scope, depth int) {
	r.walk(n.X, s, depth)
	inner := nested(s)

	for _, expression := range []ast.Expr{n.Key, n.Value} {
		if id, ok := expression.(*ast.Ident); ok && n.Tok == token.DEFINE {
			r.declare(inner, id, nil)
		} else {
			r.walk(expression, inner, depth)
		}
	}

	r.walk(n.Body, inner, depth)
}

func (r *resolver) typeSwitch(n *ast.TypeSwitchStmt, s *scope, depth int) {
	inner := nested(s)
	r.walk(n.Init, inner, depth)

	var guard *ast.Ident
	if assignment, ok := n.Assign.(*ast.AssignStmt); ok && assignment.Tok == token.DEFINE && len(assignment.Lhs) == 1 {
		guard, _ = assignment.Lhs[0].(*ast.Ident)
		for _, expression := range assignment.Rhs {
			r.walk(expression, inner, depth)
		}
	} else {
		r.walk(n.Assign, inner, depth)
	}

	if n.Body == nil {
		return
	}

	for _, statement := range n.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			continue
		}

		for _, expression := range clause.List {
			r.walk(expression, inner, depth)
		}

		branch := nested(inner)
		if guard != nil && guard.Name != "_" {
			// The type-switch guard declares a different variable in each case.
			branch.names[guard.Name] = &Binding{}
		}

		r.statements(clause.Body, branch, depth)

		if r.err != nil {
			return
		}
	}
}
