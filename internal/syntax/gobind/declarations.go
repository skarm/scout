package gobind

import (
	"go/ast"
	"go/token"
)

func (r *resolver) predeclare(declaration ast.Decl, s *scope) {
	switch n := declaration.(type) {
	case *ast.FuncDecl:
		if n.Recv == nil {
			r.declare(s, n.Name, nil)
		}
	case *ast.GenDecl:
		for _, spec := range n.Specs {
			switch value := spec.(type) {
			case *ast.ValueSpec:
				r.valueNames(n.Tok, value, s)
			case *ast.TypeSpec:
				r.declare(s, value.Name, nil)
			}
		}
	}
}

func (r *resolver) valueNames(kind token.Token, spec *ast.ValueSpec, s *scope) {
	for i, name := range spec.Names {
		var constant ast.Expr
		if kind == token.CONST && len(spec.Names) == len(spec.Values) {
			constant = spec.Values[i]
		}

		r.declare(s, name, constant)
	}
}

func (r *resolver) declaration(n *ast.GenDecl, s *scope, depth int) {
	for _, spec := range n.Specs {
		switch value := spec.(type) {
		case *ast.ValueSpec:
			r.walk(value.Type, s, depth)

			for _, expression := range value.Values {
				r.walk(expression, s, depth)
			}

			r.valueNames(n.Tok, value, s)
		case *ast.TypeSpec:
			r.declare(s, value.Name, nil)
			inner := nested(s)
			r.fieldNames(value.TypeParams, inner)
			r.fieldTypes(value.TypeParams, inner, depth)
			r.walk(value.Type, inner, depth)
		}

		if r.err != nil {
			return
		}
	}
}

func (r *resolver) fieldNames(fields *ast.FieldList, s *scope) {
	if fields != nil {
		for _, field := range fields.List {
			for _, name := range field.Names {
				r.declare(s, name, nil)
			}
		}
	}
}

func (r *resolver) fieldTypes(fields *ast.FieldList, s *scope, depth int) {
	if fields != nil {
		for _, field := range fields.List {
			r.walk(field.Type, s, depth)
		}
	}
}

func (r *resolver) function(signature *ast.FuncType, receiver *ast.FieldList, body *ast.BlockStmt, parent *scope, depth int) {
	if signature == nil {
		return
	}

	s := nested(parent)
	r.fieldNames(signature.TypeParams, s)
	r.receiverParameters(receiver, s)
	r.fieldTypes(signature.TypeParams, s, depth)
	// Parameter names are not visible in the signature's type expressions.
	r.fieldTypes(receiver, s, depth)
	r.fieldTypes(signature.Params, s, depth)
	r.fieldTypes(signature.Results, s, depth)
	r.fieldNames(receiver, s)
	r.fieldNames(signature.Params, s)
	r.fieldNames(signature.Results, s)

	if body != nil {
		// Parameters and the outermost function block share a lexical scope.
		r.statements(body.List, s, depth)
	}
}

func (r *resolver) receiverParameters(receiver *ast.FieldList, s *scope) {
	if receiver == nil {
		return
	}

	for _, field := range receiver.List {
		typ := field.Type
		if pointer, ok := typ.(*ast.StarExpr); ok {
			typ = pointer.X
		}

		var parameters []ast.Expr

		switch indexed := typ.(type) {
		case *ast.IndexExpr:
			parameters = []ast.Expr{indexed.Index}
		case *ast.IndexListExpr:
			parameters = indexed.Indices
		}

		for _, parameter := range parameters {
			if name, ok := parameter.(*ast.Ident); ok {
				r.declare(s, name, nil)
			}
		}
	}
}
