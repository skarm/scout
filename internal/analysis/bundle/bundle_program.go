package bundle

import (
	"errors"
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

const (
	nodeArray     = "array-value"
	nodeReturn    = "return"
	nodeName      = "name"
	nodeLiteral   = "literal"
	nodeAssign    = "assign"
	nodeIndex     = "index"
	nodeMember    = "member"
	nodeCall      = "call"
	nodeConcat    = "concat"
	nodeBranch    = "branch"
	nodeAggregate = "aggregate"
)

type bundleNode struct {
	kind, name, text string
	known            bool
	span             source.Span
	children         []*bundleNode
}
type bundleImport struct {
	module, symbol string
	local          bool
}
type bundleFunction struct {
	program  *bundleProgram
	name     string
	params   []string
	body     []*bundleNode
	exported bool
}
type bundleProgram struct {
	file, language, pkg       string
	unit                      document.Unit
	imports                   map[string]bundleImport
	functions                 map[string]*bundleFunction
	body                      []*bundleNode
	buildingFunction          int
	globals                   map[string]bundleValue
	initialized, initializing bool
}

func (b *bundleAnalysis) buildPrograms(d document.File) {
	for _, u := range d.Units() {
		if u.Origin != "file" {
			continue
		}

		p := &bundleProgram{
			file:      d.Artifact().Metadata().Path,
			language:  u.Language,
			unit:      u,
			imports:   map[string]bundleImport{},
			functions: map[string]*bundleFunction{},
		}
		switch t := u.Tree.(type) {
		case parse.PythonTree:
			if t.Root == nil {
				continue
			}

			p.body = b.pythonNodes(p, t.Root.List(frontend.Body), 0)
		case scriptsyntax.Tree:
			if t.Root == nil {
				continue
			}

			p.body = b.scriptNodes(p, t.Root.Children, 0)
		case parse.GoTree:
			if t.Tree == nil {
				continue
			}

			b.buildGo(p, t)
		default:
			continue
		}

		b.programs[p.file] = p
	}
}

func (b *bundleAnalysis) newNode(p *bundleProgram, start, end int) *bundleNode {
	if !b.step() || end <= start {
		return nil
	}

	s, e := p.unit.View.Original(source.Span{Start: start, End: end})
	if e != nil {
		return nil
	}

	return &bundleNode{kind: nodeAggregate, span: s}
}

func (b *bundleAnalysis) pythonNodes(p *bundleProgram, nodes []*frontend.Node, depth int) []*bundleNode {
	var out []*bundleNode

	for _, n := range nodes {
		if v := b.pythonNode(p, n, depth+1); v != nil {
			out = append(out, v)
		}
	}

	return out
}

func (b *bundleAnalysis) pythonNode(p *bundleProgram, n *frontend.Node, depth int) *bundleNode {
	if depth > 64 {
		b.gap = errors.New("python bundle projection depth limit")
		return nil
	}

	if n == nil {
		return nil
	}

	out := b.newNode(p, n.Start, n.End)
	if out == nil {
		return nil
	}

	child := func(n *frontend.Node) *bundleNode { return b.pythonNode(p, n, depth+1) }
	switch n.Kind() {
	case frontend.FunctionDef, frontend.AsyncFunctionDef:
		if p.buildingFunction > 0 {
			b.gap = errors.New("nested Python bundle functions are unresolved")
			return nil
		}

		fn := &bundleFunction{program: p, name: n.String(frontend.FieldName), exported: true}

		args := n.Child(frontend.Args)
		for _, key := range []frontend.FieldKind{frontend.Posonlyargs, frontend.Args, frontend.KWOnlyargs} {
			for _, arg := range args.List(key) {
				fn.params = append(fn.params, arg.String(frontend.FieldArg))
			}
		}

		p.buildingFunction++
		fn.body = b.pythonNodes(p, n.List(frontend.Body), depth+1)
		p.buildingFunction--
		p.functions[fn.name] = fn

		return nil
	case frontend.Import, frontend.ImportFrom:
		b.pythonImports(p, n)
		return nil
	case frontend.Name:
		out.kind, out.name = nodeName, n.String(frontend.ID)
	case frontend.Constant:
		out.kind = nodeLiteral
		out.text, out.known = n.Field(frontend.FieldValue).Text()
	case frontend.List, frontend.Tuple:
		out.kind = nodeArray
		out.children = b.pythonNodes(p, n.List(frontend.Elts), depth+1)
	case frontend.Attribute:
		out.kind, out.name = nodeMember, n.String(frontend.Attr)
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}
	case frontend.Subscript:
		out.kind = nodeIndex
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue)), child(n.Child(frontend.Slice))}
	case frontend.Call:
		out.kind = nodeCall
		out.children = append(out.children, child(n.Child(frontend.Func)))

		out.children = append(out.children, b.pythonNodes(p, n.List(frontend.Args), depth+1)...)
		for _, kw := range n.List(frontend.Keywords) {
			v := child(kw.Child(frontend.FieldValue))
			if v != nil {
				out.children = append(out.children, v)
			}
		}
	case frontend.Return:
		out.kind = nodeReturn
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}
	case frontend.Assign, frontend.AnnAssign, frontend.NamedExpr:
		out.kind = nodeAssign

		out.children = append(out.children, child(n.Child(frontend.FieldValue)))
		for _, target := range n.List(frontend.Targets) {
			if target.Kind() == frontend.Name {
				out.name = target.String(frontend.ID)
				break
			}
		}

		if out.name == "" {
			out.name = n.Child(frontend.Target).String(frontend.ID)
		}
	case frontend.If, frontend.For, frontend.AsyncFor, frontend.While, frontend.Try, frontend.With, frontend.AsyncWith:
		out.kind = nodeBranch
		out.children = b.pythonNodes(p, n.Children(), depth+1)
	case frontend.BinOp:
		out.kind = nodeConcat
		out.children = []*bundleNode{child(n.Child(frontend.Left)), child(n.Child(frontend.Right))}
	default:
		out.children = b.pythonNodes(p, n.Children(), depth+1)
	}

	return out
}

func scriptText(p *bundleProgram, n *scriptsyntax.Node) string {
	if n == nil || n.Start < 0 || n.End > len(p.unit.View.Text()) {
		return ""
	}

	return p.unit.View.Text()[n.Start:n.End]
}

func bundleScriptLiteral(s string) (string, bool) {
	if len(s) < 2 || s[0] != s[len(s)-1] || (s[0] != '\'' && s[0] != '"' && s[0] != '`') {
		return "", false
	}

	if s[0] == '`' && strings.Contains(s, "${") {
		return "", false
	}

	var out strings.Builder

	for rest := s[1 : len(s)-1]; rest != ""; {
		r, _, tail, e := strconv.UnquoteChar(rest, s[0])
		if e != nil {
			return "", false
		}

		out.WriteRune(r)

		rest = tail
	}

	return out.String(), true
}

func (b *bundleAnalysis) scriptNodes(p *bundleProgram, nodes []*scriptsyntax.Node, depth int) []*bundleNode {
	var out []*bundleNode

	for _, n := range nodes {
		if v := b.scriptNode(p, n, depth+1, false); v != nil {
			out = append(out, v)
		}
	}

	return out
}

func (b *bundleAnalysis) scriptNode(p *bundleProgram, n *scriptsyntax.Node, depth int, exported bool) *bundleNode {
	if depth > 64 {
		b.gap = errors.New("script bundle projection depth limit")
		return nil
	}

	if n == nil || n.Invalid {
		return nil
	}

	out := b.newNode(p, n.Start, n.End)
	if out == nil {
		return nil
	}

	child := func(n *scriptsyntax.Node) *bundleNode { return b.scriptNode(p, n, depth+1, false) }
	switch n.Kind {
	case "comment":
		return nil
	case "export_statement":
		for _, c := range n.Children {
			if v := b.scriptNode(p, c, depth+1, true); v != nil {
				out.children = append(out.children, v)
			}
		}
	case "import_statement":
		b.scriptImport(p, n)
		return nil
	case "function_declaration", "generator_function_declaration":
		b.scriptFunction(p, n, depth, exported)
		return nil
	case "identifier", "property_identifier", "shorthand_property_identifier":
		out.kind, out.name = nodeName, scriptText(p, n)
	case "string", "template_string":
		out.kind = nodeLiteral

		out.text, out.known = bundleScriptLiteral(scriptText(p, n))
		if !out.known {
			out.kind = nodeAggregate
			out.children = b.scriptNodes(p, n.Children, depth+1)
		}
	case "array":
		out.kind = nodeArray
		out.children = b.scriptArray(p, n.Children, depth)
	case "member_expression":
		out.kind, out.name = nodeMember, scriptText(p, n.Child("property"))
		out.children = []*bundleNode{child(n.Child("object"))}
	case "subscript_expression":
		out.kind = nodeIndex
		out.children = []*bundleNode{child(n.Child("object")), child(n.Child("index"))}
	case "call_expression", "new_expression":
		out.kind = nodeCall

		callee := n.Child("function")
		if callee == nil {
			callee = n.Child("constructor")
		}

		out.children = append(out.children, child(callee))

		if args := n.Child("arguments"); args != nil {
			for _, c := range args.Children {
				if c.Kind != "(" && c.Kind != ")" && c.Kind != "," {
					out.children = append(out.children, child(c))
				}
			}
		}
	case "return_statement":
		out.kind = nodeReturn
		out.children = b.scriptNodes(p, n.Children, depth+1)
	case "variable_declarator":
		out.kind, out.name = nodeAssign, scriptText(p, n.Child("name"))
		out.children = []*bundleNode{child(n.Child("value"))}
	case "assignment_expression":
		out.kind, out.name = nodeAssign, scriptText(p, n.Child("left"))
		out.children = []*bundleNode{child(n.Child("right"))}
	case "binary_expression":
		out.kind = nodeConcat
		out.children = []*bundleNode{child(n.Child("left")), child(n.Child("right"))}
	case "pair":
		out.children = []*bundleNode{child(n.Child("value"))}
	case "if_statement", "for_statement", "while_statement", "try_statement", "switch_statement":
		out.kind = nodeBranch
		out.children = b.scriptNodes(p, n.Children, depth+1)
	default:
		out.children = b.scriptNodes(p, n.Children, depth+1)
	}

	return out
}

func (b *bundleAnalysis) scriptArray(p *bundleProgram, children []*scriptsyntax.Node, depth int) []*bundleNode {
	var out []*bundleNode

	for _, c := range children {
		if c.Kind != "[" && c.Kind != "]" && c.Kind != "," {
			out = append(out, b.scriptNode(p, c, depth+1, false))
		}
	}

	return out
}

func (b *bundleAnalysis) goStatements(p *bundleProgram, fs *token.FileSet, stmts []ast.Stmt, depth int) []*bundleNode {
	var out []*bundleNode

	for _, s := range stmts {
		if depth > 64 {
			b.gap = errors.New("go bundle projection depth limit")
			break
		}

		if !b.step() {
			break
		}

		n := b.newNode(p, fs.PositionFor(s.Pos(), false).Offset, fs.PositionFor(s.End(), false).Offset)
		if n == nil {
			continue
		}

		switch s := s.(type) {
		case *ast.ExprStmt:
			n = b.goExpr(p, fs, s.X, depth+1)
		case *ast.ReturnStmt:
			n.kind = nodeReturn
			for _, e := range s.Results {
				n.children = append(n.children, b.goExpr(p, fs, e, depth+1))
			}
		case *ast.AssignStmt:
			for i, e := range s.Lhs {
				if id, ok := e.(*ast.Ident); ok {
					v := *n

					v.kind, v.name = nodeAssign, id.Name
					if i < len(s.Rhs) {
						v.children = []*bundleNode{b.goExpr(p, fs, s.Rhs[i], depth+1)}
					}

					out = append(out, &v)
				}
			}

			continue
		case *ast.DeclStmt:
			out = append(out, b.goDeclarations(p, fs, s, n, depth)...)
			continue
		case *ast.BlockStmt:
			n.children = b.goStatements(p, fs, s.List, depth+1)
		case *ast.IfStmt:
			n.kind = nodeBranch
			n.children = append(n.children, b.goExpr(p, fs, s.Cond, depth+1))

			n.children = append(n.children, b.goStatements(p, fs, s.Body.List, depth+1)...)
			if s.Else != nil {
				n.children = append(n.children, b.goStatements(p, fs, []ast.Stmt{s.Else}, depth+1)...)
			}
		case *ast.ForStmt:
			n.kind = nodeBranch
			n.children = b.goStatements(p, fs, s.Body.List, depth+1)
		case *ast.RangeStmt:
			n.kind = nodeBranch
			n.children = b.goStatements(p, fs, s.Body.List, depth+1)
		default:
			continue
		}

		if n != nil {
			out = append(out, n)
		}
	}

	return out
}

func (b *bundleAnalysis) goExpr(p *bundleProgram, fs *token.FileSet, e ast.Expr, depth int) *bundleNode {
	if depth > 64 {
		b.gap = errors.New("go bundle expression depth limit")
		return nil
	}

	if e == nil {
		return nil
	}

	n := b.newNode(p, fs.PositionFor(e.Pos(), false).Offset, fs.PositionFor(e.End(), false).Offset)
	if n == nil {
		return nil
	}

	child := func(e ast.Expr) *bundleNode { return b.goExpr(p, fs, e, depth+1) }
	switch e := e.(type) {
	case *ast.Ident:
		n.kind, n.name = nodeName, e.Name
	case *ast.BasicLit:
		n.kind = nodeLiteral

		if e.Kind == token.STRING {
			var err error

			n.text, err = strconv.Unquote(e.Value)
			n.known = err == nil
		}
	case *ast.SelectorExpr:
		n.kind, n.name = nodeMember, e.Sel.Name
		n.children = []*bundleNode{child(e.X)}
	case *ast.CallExpr:
		n.kind = nodeCall

		n.children = append(n.children, child(e.Fun))
		for _, a := range e.Args {
			n.children = append(n.children, child(a))
		}
	case *ast.ParenExpr:
		return child(e.X)
	case *ast.BinaryExpr:
		n.kind = nodeConcat
		n.children = []*bundleNode{child(e.X), child(e.Y)}
	case *ast.IndexExpr:
		n.kind = nodeIndex
		n.children = []*bundleNode{child(e.X), child(e.Index)}
	case *ast.KeyValueExpr:
		n.children = []*bundleNode{child(e.Value)}
	case *ast.CompositeLit:
		if _, ok := e.Type.(*ast.ArrayType); ok {
			n.kind = nodeArray
		}

		for _, v := range e.Elts {
			n.children = append(n.children, child(v))
		}
	case *ast.UnaryExpr:
		n.children = []*bundleNode{child(e.X)}
	default:
		return nil
	}

	return n
}

func (b *bundleAnalysis) buildGo(p *bundleProgram, t parse.GoTree) {
	p.pkg = t.Tree.Name.Name
	for _, imp := range t.Tree.Imports {
		module, e := strconv.Unquote(imp.Path.Value)
		if e != nil {
			continue
		}

		name := path.Base(module)
		if imp.Name != nil {
			name = imp.Name.Name
		}

		p.imports[name] = bundleImport{module: module}
	}

	for _, decl := range t.Tree.Decls {
		if d, ok := decl.(*ast.GenDecl); ok && (d.Tok == token.VAR || d.Tok == token.CONST) {
			n := b.newNode(p, t.Tokens.PositionFor(d.Pos(), false).Offset, t.Tokens.PositionFor(d.End(), false).Offset)
			if n != nil {
				p.body = append(p.body, b.goDeclarations(p, t.Tokens, &ast.DeclStmt{Decl: d}, n, 0)...)
			}
		}

		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv == nil {
			f := &bundleFunction{program: p, name: fn.Name.Name, exported: ast.IsExported(fn.Name.Name)}
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					for _, name := range field.Names {
						f.params = append(f.params, name.Name)
					}
				}
			}

			f.body = b.goStatements(p, t.Tokens, fn.Body.List, 0)
			p.functions[f.name] = f
		}
	}
}

func (b *bundleAnalysis) pythonImports(p *bundleProgram, n *frontend.Node) {
	module := n.String(frontend.FieldModule)

	level, _ := n.Field(frontend.Level).Integer()
	for _, alias := range n.List(frontend.Names) {
		name, as := alias.String(frontend.FieldName), alias.String(frontend.Asname)
		if as == "" {
			as = name
		}

		if n.Kind() == frontend.Import {
			p.imports[as] = bundleImport{module: name, local: true}
		} else {
			prefix := ""
			if level > 0 {
				prefix = strings.Repeat(".", int(level))
			}

			p.imports[as] = bundleImport{module: prefix + module, symbol: name, local: true}
		}
	}
}

func (b *bundleAnalysis) scriptImport(p *bundleProgram, n *scriptsyntax.Node) {
	module, ok := bundleScriptLiteral(scriptText(p, n.Child("source")))
	if !ok {
		return
	}

	module = strings.TrimPrefix(module, "node:")

	var walk func(*scriptsyntax.Node)

	walk = func(n *scriptsyntax.Node) {
		if n == nil || !b.step() {
			return
		}

		switch n.Kind {
		case "import_specifier":
			name := scriptText(p, n.Child("name"))

			alias := scriptText(p, n.Child("alias"))
			if alias == "" {
				alias = name
			}

			p.imports[alias] = bundleImport{module: module, symbol: name, local: strings.HasPrefix(module, ".")}

			return
		case "namespace_import":
			for _, c := range n.Children {
				if c.Kind == "identifier" {
					p.imports[scriptText(p, c)] = bundleImport{module: module, local: strings.HasPrefix(module, ".")}
				}
			}

			return
		case "import_clause":
			for _, c := range n.Children {
				if c.Kind == "identifier" {
					symbol := ""
					if strings.HasPrefix(module, ".") {
						symbol = "default"
					}

					p.imports[scriptText(p, c)] = bundleImport{
						module: strings.TrimPrefix(module, "node:"),
						symbol: symbol,
						local:  strings.HasPrefix(module, "."),
					}
				}
			}
		}

		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(n)
}

func (b *bundleAnalysis) scriptFunction(p *bundleProgram, n *scriptsyntax.Node, depth int, exported bool) {
	if p.buildingFunction > 0 {
		b.gap = errors.New("nested script bundle functions are unresolved")
		return
	}

	fn := &bundleFunction{program: p, name: scriptText(p, n.Child("name")), exported: exported}
	if params := n.Child("parameters"); params != nil {
		for _, c := range params.Children {
			if c.Kind == "identifier" {
				fn.params = append(fn.params, scriptText(p, c))
			} else if name := c.Child("pattern"); name != nil {
				fn.params = append(fn.params, scriptText(p, name))
			}
		}
	}

	if body := n.Child("body"); body != nil {
		p.buildingFunction++
		fn.body = b.scriptNodes(p, body.Children, depth+1)
		p.buildingFunction--
	}

	p.functions[fn.name] = fn
}

func (b *bundleAnalysis) goDeclarations(p *bundleProgram, fs *token.FileSet, s *ast.DeclStmt, n *bundleNode, depth int) []*bundleNode {
	var out []*bundleNode

	if d, ok := s.Decl.(*ast.GenDecl); ok {
		for _, spec := range d.Specs {
			if v, ok := spec.(*ast.ValueSpec); ok {
				for i, id := range v.Names {
					x := *n

					x.kind, x.name = nodeAssign, id.Name
					if i < len(v.Values) {
						x.children = []*bundleNode{b.goExpr(p, fs, v.Values[i], depth+1)}
					}

					out = append(out, &x)
				}
			}
		}
	}

	return out
}
