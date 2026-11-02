package bundle

import (
	"errors"
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

const (
	nodeArray       = "array-value"
	nodeObject      = "object-value"
	nodeReturn      = "return"
	nodeName        = "name"
	nodeLiteral     = "literal"
	nodeFunction    = "function-value"
	nodeAssign      = "assign"
	nodeAssignGroup = "parallel-assign"
	nodeDeclare     = "declare-if-absent"
	nodeMutate      = "compound-write"
	nodeIndex       = "index"
	nodeMember      = "member"
	nodeCall        = "call"
	nodeConstruct   = "construct"
	nodeConcat      = "concat"
	nodeBranch      = "branch"
	nodeAggregate   = "aggregate"
	nodeScope       = "lexical-scope"
	nodeSequence    = "sequence"
	nodeStatement   = "expression-statement"
	nodeResolver    = "resolver-value"
	nodeAddress     = "address-value"
	nodeWrite       = "member-write"
	nodeAwait       = "await-value"
)

type bundleNode struct {
	kind, name, text string
	known            bool
	credential       bool
	span             source.Span
	children         []*bundleNode
	function         *bundleFunction
	locals           map[string]bool
	globalWrite      bool
	rebind           bool
	valueFirst       bool     // Python plain member assignment evaluates the RHS first.
	argumentNames    []string // Python call arguments: empty=positional, *=unresolved expansion.
}
type bundleImport struct {
	module, symbol string
	local          bool
}
type bundleFunction struct {
	program  *bundleProgram
	name     string
	params   []string
	locals   map[string]bool
	body     []*bundleNode
	exported bool
	self     string
	python   *bundlePythonParameters
}
type bundlePythonParameters struct {
	positionalOnly, positional int
	required                   []bool
}
type bundleProgram struct {
	file, language, pkg       string
	unit                      document.Unit
	imports                   map[string]bundleImport
	functions                 map[string]*bundleFunction
	exports                   map[string]string
	declared                  map[string]bool
	body                      []*bundleNode
	buildingFunction          int
	scriptScopes              []map[string]bool
	globals                   map[string]bundleValue
	initialized, initializing bool
	failed                    bool
	embedded                  bool
}

func (b *bundleAnalysis) buildPrograms(d document.File) {
	for _, u := range d.Units() {
		if u.Origin != "file" && u.Origin != "fenced-code" {
			continue
		}

		p := &bundleProgram{
			file:      d.Artifact().Metadata().Path,
			language:  u.Language,
			unit:      u,
			imports:   map[string]bundleImport{},
			functions: map[string]*bundleFunction{},
			exports:   map[string]string{},
			embedded:  u.Origin != "file",
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

			p.declared = map[string]bool{}
			b.scriptFunctionLocals(p, t.Root.Children, p.declared, true, 0)
			p.body = b.scriptNodes(p, t.Root.Children, 0)
		case parse.GoTree:
			if t.Tree == nil {
				continue
			}

			b.buildGo(p, t)
		default:
			continue
		}

		if p.embedded {
			// A fence is an independent program, not an importable module or
			// an implicit part of nearby source files' Go packages.
			b.embedded = append(b.embedded, p)
		} else {
			b.programs[p.file] = p
		}
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

		fn := &bundleFunction{program: p, name: n.String(frontend.FieldName), exported: true, locals: map[string]bool{}}

		if pythonParameters(fn, n.Child(frontend.Args)) {
			b.gap = errors.New("dynamic Python parameter defaults are unresolved")
		}

		b.pythonAnnotationLocals(n.List(frontend.Body), fn.locals, 0)

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

		return b.literalNode(out)
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
		b.pythonCallArguments(p, n, out, depth)
	case frontend.Return:
		out.kind = nodeReturn
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}
	case frontend.Expr:
		out.kind = nodeStatement
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}
	case frontend.Assign, frontend.AnnAssign, frontend.NamedExpr, frontend.AugAssign:
		return b.pythonAssignment(p, n, out, depth)
	case frontend.Global, frontend.Nonlocal:
		out.kind, out.globalWrite = nodeAssign, true
	case frontend.Delete:
		// Deletion can invalidate a binding or a class method across frames.
		// Retain observations in target expressions, then stop unsupported state.
		out.kind, out.globalWrite = nodeAssign, true
		out.children = []*bundleNode{{kind: nodeAggregate, children: b.pythonNodes(p, n.List(frontend.Targets), depth+1)}}
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

func (b *bundleAnalysis) pythonAnnotationLocals(nodes []*frontend.Node, names map[string]bool, depth int) {
	if depth > 64 {
		b.err = errors.New("python local annotation binding depth limit")
		return
	}

	for _, n := range nodes {
		if !b.step() {
			return
		}

		switch n.Kind() {
		case frontend.FunctionDef, frontend.AsyncFunctionDef, frontend.ClassDef:
			continue
		case frontend.AnnAssign:
			if target := n.Child(frontend.Target); target != nil && target.Kind() == frontend.Name {
				names[target.String(frontend.ID)] = true
			}
		default:
			b.pythonAnnotationLocals(n.Children(), names, depth+1)
		}
	}
}

func (b *bundleAnalysis) pythonAssignment(p *bundleProgram, n *frontend.Node, out *bundleNode, depth int) *bundleNode {
	child := func(n *frontend.Node) *bundleNode { return b.pythonNode(p, n, depth+1) }
	targets := n.List(frontend.Targets)

	target := n.Child(frontend.Target)
	if len(targets) > 0 {
		target = targets[0]
	}

	if n.Kind() == frontend.AnnAssign && n.Child(frontend.FieldValue) == nil {
		// Annotation-only statements evaluate the receiver/index without
		// writing the attribute, item or name being annotated.
		if target := pythonMemberTarget(n); target != nil {
			out.children = []*bundleNode{child(target.Child(frontend.FieldValue))}
			if target.Kind() == frontend.Subscript {
				out.children = append(out.children, child(target.Child(frontend.Slice)))
			}
		}

		return out
	}

	if len(targets) > 1 || target != nil && (target.Kind() == frontend.Tuple || target.Kind() == frontend.List) {
		// Partial assignment would leave a stale resolver or function binding.
		// Evaluate the RHS, then stop this unsupported write before later sinks.
		out.kind, out.globalWrite = nodeAssign, true
		out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}

		return out
	}

	if target := pythonMemberTarget(n); target != nil {
		out.kind = nodeWrite
		out.valueFirst = n.Kind() != frontend.AugAssign
		out.children = []*bundleNode{child(target.Child(frontend.FieldValue))}

		if target.Kind() == frontend.Attribute {
			out.name, out.known = target.String(frontend.Attr), true
		} else {
			out.children = append(out.children, child(target.Child(frontend.Slice)))
		}

		out.children = append(out.children, child(n.Child(frontend.FieldValue)))

		return out
	}

	out.kind, out.name = nodeAssign, target.String(frontend.ID)
	if n.Kind() == frontend.AugAssign {
		out.kind = nodeMutate
	}

	out.children = []*bundleNode{child(n.Child(frontend.FieldValue))}

	return out
}

func pythonMemberTarget(n *frontend.Node) *frontend.Node {
	target := n.Child(frontend.Target)
	if targets := n.List(frontend.Targets); len(targets) > 0 {
		target = targets[0]
	}

	if target != nil && (target.Kind() == frontend.Attribute || target.Kind() == frontend.Subscript) {
		return target
	}

	return nil
}

func pythonParameters(fn *bundleFunction, args *frontend.Node) bool {
	posonly, positional, kwonly := args.List(frontend.Posonlyargs), args.List(frontend.Args), args.List(frontend.KWOnlyargs)
	fn.python = &bundlePythonParameters{positionalOnly: len(posonly), positional: len(posonly) + len(positional)}

	for _, group := range [][]*frontend.Node{posonly, positional, kwonly} {
		for _, arg := range group {
			fn.params = append(fn.params, arg.String(frontend.FieldArg))
			fn.python.required = append(fn.python.required, true)
		}
	}

	dynamic := false
	for i, value := range args.List(frontend.Defaults) {
		dynamic = dynamic || value != nil && value.Kind() != frontend.Constant

		index := fn.python.positional - len(args.List(frontend.Defaults)) + i
		if index >= 0 && index < fn.python.positional {
			fn.python.required[index] = false
		}
	}

	for i, value := range args.List(frontend.KWDefaults) {
		dynamic = dynamic || value != nil && value.Kind() != frontend.Constant
		if index := fn.python.positional + i; value != nil && index < len(fn.params) {
			fn.python.required[index] = false
		}
	}

	return dynamic
}

func (b *bundleAnalysis) pythonCallArguments(p *bundleProgram, n *frontend.Node, out *bundleNode, depth int) {
	for _, arg := range n.List(frontend.Args) {
		if v := b.pythonNode(p, arg, depth+1); v != nil {
			name := ""
			if arg.Kind() == frontend.Starred {
				name = "*"
			}

			out.children = append(out.children, v)
			out.argumentNames = append(out.argumentNames, name)
		}
	}

	for _, kw := range n.List(frontend.Keywords) {
		if v := b.pythonNode(p, kw.Child(frontend.FieldValue), depth+1); v != nil {
			name := kw.String(frontend.FieldArg)
			if name == "" {
				name = "*"
			}

			out.children = append(out.children, v)
			out.argumentNames = append(out.argumentNames, name)
		}
	}
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
	return b.scriptNodesExported(p, nodes, depth, false)
}

func (b *bundleAnalysis) scriptNodesExported(p *bundleProgram, nodes []*scriptsyntax.Node, depth int, exported bool) []*bundleNode {
	var out []*bundleNode

	for _, n := range nodes {
		if v := b.scriptNode(p, n, depth+1, exported); v != nil {
			out = append(out, v)
		}
	}

	return out
}

func (b *bundleAnalysis) scriptNode(p *bundleProgram, n *scriptsyntax.Node, depth int, exported bool) *bundleNode {
	if depth > 64 {
		b.err = errors.New("script bundle projection depth limit")
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
		return b.scriptExport(p, n, out, depth)
	case "import_statement":
		b.scriptImport(p, n)
		return nil
	case "function_declaration":
		b.scriptFunctionDeclaration(p, n, depth, exported)
		return nil
	case "arrow_function", "function_expression":
		out.kind, out.function = nodeFunction, b.scriptFunction(p, n, depth)
	case "generator_function_declaration", "generator_function", "class_declaration", "class", "method_definition":
		b.gap = errors.New("script generator, class or method bundle values are unresolved")
		return nil
	case "lexical_declaration", "variable_declaration":
		out.children = b.scriptDeclarations(p, n, depth, exported)
	case "statement_block", "catch_clause", "for_statement", "for_in_statement", "switch_body":
		return b.scriptScope(p, n, out, depth)
	case "sequence_expression":
		out.kind = nodeSequence
		out.children = b.scriptArray(p, n.Children, depth)
	case "await_expression":
		out.kind = nodeAwait
		out.children = []*bundleNode{b.scriptValue(p, n, depth)}
	case "parenthesized_expression", "as_expression", "satisfies_expression", "type_assertion", "non_null_expression":
		return b.scriptValue(p, n, depth)
	case "identifier", "property_identifier", "shorthand_property_identifier":
		out.kind, out.name = nodeName, scriptText(p, n)
	case "string", "template_string":
		return b.scriptLiteral(p, n, out, depth)
	case "array", "object":
		return b.scriptCollection(p, n, out, depth)
	case "member_expression":
		out.kind, out.name = nodeMember, scriptText(p, n.Child("property"))
		out.children = []*bundleNode{child(n.Child("object"))}
	case "subscript_expression":
		out.kind = nodeIndex
		out.children = []*bundleNode{child(n.Child("object")), child(n.Child("index"))}
	case "call_expression", "new_expression":
		return b.scriptCallNode(p, n, out, depth)
	case "return_statement", "expression_statement":
		return b.scriptStatement(p, n, out, depth)
	case "variable_declarator":
		return b.scriptDeclaration(p, n, out, depth, exported)
	case "assignment_expression":
		return b.scriptAssignment(p, n, out, depth)
	case "augmented_assignment_expression", "update_expression":
		return b.scriptMutation(p, n, out, depth)
	case "unary_expression":
		return b.scriptUnary(p, n, out, depth)
	case "binary_expression":
		out.kind = nodeConcat
		out.children = []*bundleNode{child(n.Child("left")), child(n.Child("right"))}
	case "pair":
		return child(n.Child("value"))
	case "if_statement", "while_statement", "try_statement", "switch_statement", "ternary_expression":
		out.kind = nodeBranch
		out.children = b.scriptNodes(p, n.Children, depth+1)
	default:
		out.children = b.scriptNodes(p, n.Children, depth+1)
	}

	return out
}

func (b *bundleAnalysis) scriptStatement(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if n.Kind == "return_statement" {
		out.kind = nodeReturn
		out.children = []*bundleNode{b.scriptValue(p, n, depth)}
	} else {
		out.kind = nodeStatement
		out.children = b.scriptNodes(p, n.Children, depth+1)
	}

	return out
}

func (b *bundleAnalysis) scriptLiteral(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	out.kind = nodeLiteral

	out.text, out.known = bundleScriptLiteral(scriptText(p, n))
	if !out.known {
		out.kind = nodeAggregate
		out.children = b.scriptNodes(p, n.Children, depth+1)
	}

	return b.literalNode(out)
}

func (b *bundleAnalysis) literalNode(n *bundleNode) *bundleNode {
	if !n.known {
		return n
	}

	// Classify once per source node. The immutable result survives fresh
	// imported-module runtime state in independent Markdown entry points.
	for offset := 0; offset < len(n.text); offset += 64 {
		if !b.step() {
			return nil
		}
	}

	n.credential = literals.HasProviderToken(n.text)

	return n
}

func (b *bundleAnalysis) scriptAssignment(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if left := n.Child("left"); left != nil && (left.Kind == "member_expression" || left.Kind == "subscript_expression") {
		return b.scriptMemberWrite(p, left, n.Child("right"), out, depth)
	}

	b.scriptBindingWrite(p, n.Child("left"), n.Child("right"), out, depth)

	return out
}

func (b *bundleAnalysis) scriptBindingWrite(p *bundleProgram, target, value *scriptsyntax.Node, out *bundleNode, depth int) {
	out.kind = nodeAssign
	out.children = []*bundleNode{b.scriptNode(p, value, depth+1, false)}

	if target != nil && target.Kind == "identifier" {
		out.name = scriptText(p, target)
	} else {
		// A partial pattern write could preserve an overwritten resolver alias.
		out.globalWrite = true
	}
}

func (b *bundleAnalysis) scriptDeclaration(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int, exported bool) *bundleNode {
	target := n.Child("name")
	b.scriptBindingWrite(p, target, n.Child("value"), out, depth)

	if out.globalWrite {
		// Declaration patterns contain local bindings, never member writes.
		// Clear each unsupported value without stopping independent inspection.
		out.globalWrite, out.locals = false, map[string]bool{}
		b.scriptBindingNames(p, target, out.locals, 0)
	}

	if exported {
		b.scriptExportBinding(p, target)
	}

	return out
}

func (b *bundleAnalysis) scriptUnary(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if scriptText(p, n.Child("operator")) == "delete" {
		out.kind, out.globalWrite = nodeAssign, true
	}

	out.children = []*bundleNode{b.scriptNode(p, n.Child("argument"), depth+1, false)}

	return out
}

func (b *bundleAnalysis) scriptMemberWrite(p *bundleProgram, left, right *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	out.kind = nodeWrite
	out.children = []*bundleNode{b.scriptNode(p, left.Child("object"), depth+1, false)}

	if left.Kind == "member_expression" {
		out.name, out.known = scriptText(p, left.Child("property")), true
	} else {
		out.children = append(out.children, b.scriptNode(p, left.Child("index"), depth+1, false))
	}

	out.children = append(out.children, b.scriptNode(p, right, depth+1, false))

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
			out = append(out, b.goAssignments(p, fs, s, n, depth)...)
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

func (b *bundleAnalysis) goAssignments(p *bundleProgram, fs *token.FileSet, s *ast.AssignStmt, at *bundleNode, depth int) []*bundleNode {
	var out []*bundleNode

	parallel := len(s.Lhs) > 1 && len(s.Lhs) == len(s.Rhs)

	for i, target := range s.Lhs {
		if id, ok := target.(*ast.Ident); ok {
			n := *at

			n.kind, n.name = nodeAssign, id.Name
			n.rebind = s.Tok != token.DEFINE

			if i < len(s.Rhs) {
				n.children = []*bundleNode{b.goExpr(p, fs, s.Rhs[i], depth+1)}
			}

			out = append(out, &n)
		} else if i < len(s.Rhs) {
			parallel = false

			if n := b.goMemberWrite(p, fs, target, s.Rhs[i], at, depth); n != nil {
				out = append(out, n)
			}
		}
	}

	if parallel {
		return assignmentGroup(at, out)
	}

	return out
}

func assignmentGroup(at *bundleNode, assignments []*bundleNode) []*bundleNode {
	n := *at
	n.kind, n.children = nodeAssignGroup, assignments

	return []*bundleNode{&n}
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
	case *ast.ArrayType:
		if element, ok := e.Elt.(*ast.Ident); ok && element.Name == "byte" && e.Len == nil {
			n.kind, n.name = nodeName, "[]byte"
		}
	case *ast.BasicLit:
		n.kind = nodeLiteral

		if e.Kind == token.STRING {
			var err error

			n.text, err = strconv.Unquote(e.Value)
			n.known = err == nil
		}

		return b.literalNode(n)
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
		return b.goComposite(p, fs, e, n, depth)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			n.kind = nodeAddress
		}

		n.children = []*bundleNode{child(e.X)}
	default:
		return nil
	}

	return n
}

func (b *bundleAnalysis) goComposite(p *bundleProgram, fs *token.FileSet, e *ast.CompositeLit, n *bundleNode, depth int) *bundleNode {
	if goResolverType(p, e.Type) {
		n.kind = nodeResolver
		n.children = append(n.children, b.goExpr(p, fs, e.Type, depth+1))

		for _, field := range e.Elts {
			if kv, ok := field.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "PreferGo" && id.Name != "StrictErrors" {
					b.gap = errors.New("custom Go resolver configuration is unresolved")
				}
			}
		}
	}

	if _, ok := e.Type.(*ast.ArrayType); ok {
		n.kind = nodeArray
	}

	for _, value := range e.Elts {
		n.children = append(n.children, b.goExpr(p, fs, value, depth+1))
	}

	return n
}

func goResolverType(p *bundleProgram, typ ast.Expr) bool {
	selector, ok := typ.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Resolver" {
		return false
	}

	qualifier, ok := selector.X.(*ast.Ident)

	return ok && p.imports[qualifier.Name].module == "net"
}

func (b *bundleAnalysis) goMemberWrite(p *bundleProgram, fs *token.FileSet, target, value ast.Expr, at *bundleNode, depth int) *bundleNode {
	n := *at
	n.kind = nodeWrite

	switch target := target.(type) {
	case *ast.SelectorExpr:
		n.name, n.known = target.Sel.Name, true
		n.children = []*bundleNode{b.goExpr(p, fs, target.X, depth+1)}
	case *ast.IndexExpr:
		n.children = []*bundleNode{b.goExpr(p, fs, target.X, depth+1), b.goExpr(p, fs, target.Index, depth+1)}
	default:
		return nil
	}

	n.children = append(n.children, b.goExpr(p, fs, value, depth+1))

	return &n
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
	module := b.scriptModuleSpecifier(p, n)

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
						module: module,
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

func (b *bundleAnalysis) scriptModuleSpecifier(p *bundleProgram, n *scriptsyntax.Node) string {
	module, ok := bundleScriptLiteral(scriptText(p, n.Child("source")))
	module = strings.TrimPrefix(module, "node:")

	if !ok || module == "" {
		b.gap = errors.New("script module specifier is unresolved")
		// Keep walking the import to retain its unknown local binding names.
		return ""
	}

	return module
}

func (b *bundleAnalysis) scriptFunction(p *bundleProgram, n *scriptsyntax.Node, depth int) *bundleFunction {
	if p.buildingFunction > 0 || n.Kind == "function_declaration" && len(p.scriptScopes) > 0 {
		b.gap = errors.New("nested script bundle functions are unresolved")
		return nil
	}

	fn := &bundleFunction{program: p, name: scriptText(p, n.Child("name")), locals: map[string]bool{}}
	if n.Kind != "function_declaration" {
		fn.self = fn.name
		// This key cannot collide with a source-level identifier. Expressions
		// enter lexical bindings only when their assignment is evaluated.
		fn.name = "*function@" + strconv.Itoa(n.Start) + "*"
	}

	var params []*scriptsyntax.Node
	if list := n.Child("parameters"); list != nil {
		params = list.Children
	} else if param := n.Child("parameter"); param != nil {
		params = []*scriptsyntax.Node{param}
	}

	for _, c := range params {
		if c.Kind == "(" || c.Kind == ")" || c.Kind == "," || c.Kind == "comment" {
			continue
		}

		name := c
		if c.Kind == "required_parameter" || c.Kind == "optional_parameter" {
			name = c.Child("pattern")
		}

		if name == nil || name.Kind != "identifier" || c.Child("value") != nil {
			b.gap = errors.New("script bundle parameter pattern is unresolved")
			return nil
		}

		fn.params = append(fn.params, scriptText(p, name))
		fn.locals[scriptText(p, name)] = true
	}

	if body := n.Child("body"); body != nil {
		p.buildingFunction++
		if body.Kind == "statement_block" {
			b.scriptFunctionLocals(p, body.Children, fn.locals, true, 0)
			fn.body = b.scriptNodes(p, body.Children, depth+1)
		} else if value := b.scriptNode(p, body, depth+1, false); value != nil {
			fn.body = []*bundleNode{{kind: nodeReturn, span: value.span, children: []*bundleNode{value}}}
		}

		p.buildingFunction--
	}

	if fn.self != "" {
		fn.locals[fn.self] = true
	}

	if b.scriptCaptures(p, fn.body, fn.locals, 0) {
		b.gap = errors.New("script block closure bindings are unresolved")
		return nil
	}

	if b.scriptNestedReturn(fn.body, false, 0) {
		b.gap = errors.New("script conditional or nested-block returns are unresolved")
		return nil
	}

	b.scriptGlobalWrites(fn.body, fn.locals, 0)

	p.functions[fn.name] = fn

	return fn
}

func (b *bundleAnalysis) goDeclarations(p *bundleProgram, fs *token.FileSet, s *ast.DeclStmt, n *bundleNode, depth int) []*bundleNode {
	var out []*bundleNode

	if d, ok := s.Decl.(*ast.GenDecl); ok {
		for _, spec := range d.Specs {
			if v, ok := spec.(*ast.ValueSpec); ok {
				var assignments []*bundleNode

				for i, id := range v.Names {
					x := *n

					x.kind, x.name = nodeAssign, id.Name
					if i < len(v.Values) {
						x.children = []*bundleNode{b.goExpr(p, fs, v.Values[i], depth+1)}
					} else if goResolverType(p, v.Type) {
						zero := *n
						zero.kind = nodeResolver
						zero.children = []*bundleNode{b.goExpr(p, fs, v.Type, depth+1)}
						x.children = []*bundleNode{&zero}
					}

					assignments = append(assignments, &x)
				}

				if len(v.Names) > 1 && len(v.Names) == len(v.Values) {
					assignments = assignmentGroup(n, assignments)
				}

				out = append(out, assignments...)
			}
		}
	}

	return out
}
