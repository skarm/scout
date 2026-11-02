package bundle

import (
	"errors"
	"maps"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func (b *bundleAnalysis) scriptExport(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if n.Child("source") != nil {
		b.gap = errors.New("script bundle re-exports are unresolved")
		return nil
	}

	defaultExport := false
	for _, c := range n.Children {
		defaultExport = defaultExport || c.Kind == "default"
		if c.Kind == "export_clause" {
			for _, spec := range c.Children {
				if spec.Kind != "export_specifier" {
					continue
				}

				name := scriptText(p, spec.Child("name"))
				alias := scriptText(p, spec.Child("alias"))

				if alias == "" {
					alias = name
				}

				p.exports[alias] = name
			}

			return nil
		}
	}

	if decl := n.Child("declaration"); decl != nil {
		if !defaultExport {
			return b.scriptNode(p, decl, depth+1, true)
		}

		if decl.Kind == "function_declaration" {
			if fn := b.scriptFunction(p, decl, depth+1); fn != nil {
				p.exports["default"] = fn.name
			}

			return nil
		}
	}

	if value := n.Child("value"); defaultExport && value != nil {
		// An export-default expression snapshots its value here; an export
		// clause or named default declaration instead refers to a live binding.
		const binding = "*default*"

		p.exports["default"] = binding
		out.kind, out.name = nodeAssign, binding
		out.children = []*bundleNode{b.scriptNode(p, value, depth+1, false)}

		return out
	}

	b.gap = errors.New("script bundle export form is unresolved")

	return nil
}

func (b *bundleAnalysis) scriptExportBinding(p *bundleProgram, name *scriptsyntax.Node) {
	if name != nil && name.Kind == "identifier" {
		binding := scriptText(p, name)
		p.exports[binding] = binding
	} else {
		b.gap = errors.New("destructured script exports are unresolved")
	}
}

func (b *bundleAnalysis) scriptValue(p *bundleProgram, n *scriptsyntax.Node, depth int) *bundleNode {
	for _, c := range n.Children {
		switch c.Kind {
		case "(", ")", "await", "return", ";", "comment", "as", "satisfies", "!", "type_arguments":
			continue
		default:
			return b.scriptNode(p, c, depth+1, false)
		}
	}

	return nil
}

func (b *bundleAnalysis) scriptCallChildren(p *bundleProgram, n *scriptsyntax.Node, depth int) []*bundleNode {
	callee := n.Child("function")
	if callee == nil {
		callee = n.Child("constructor")
	}

	out := []*bundleNode{b.scriptNode(p, callee, depth+1, false)}

	if args := n.Child("arguments"); args != nil {
		for _, c := range args.Children {
			if c.Kind == "spread_element" {
				b.gap = errors.New("spread script bundle arguments are unresolved")
				// Preserve observations in argument expressions, but do not bind
				// an unknown argument sequence to fixed parameter positions.
				out[0] = nil
			}

			if c.Kind != "(" && c.Kind != ")" && c.Kind != "," && c.Kind != "comment" {
				out = append(out, b.scriptNode(p, c, depth+1, false))
			}
		}
	}

	return out
}

func (b *bundleAnalysis) scriptDeclarations(p *bundleProgram, n *scriptsyntax.Node, depth int, exported bool) []*bundleNode {
	var out []*bundleNode

	for _, c := range n.Children {
		v := b.scriptNode(p, c, depth+1, exported)
		if v == nil {
			continue
		}

		if n.Kind == "variable_declaration" && c.Kind == "variable_declarator" && c.Child("value") == nil {
			v.kind = nodeDeclare
		}

		out = append(out, v)
	}

	return out
}

func (b *bundleAnalysis) scriptScope(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	out.kind, out.locals = nodeScope, map[string]bool{}
	b.scriptBindingNames(p, n.Child("parameter"), out.locals, 0)

	if n.Kind == "for_in_statement" {
		b.scriptIteratorBinding(p, n, out.locals, false)
	}

	b.scriptScopeBindings(p, n.Children, out.locals, 0)

	p.scriptScopes = append(p.scriptScopes, out.locals)
	out.children = b.scriptNodes(p, n.Children, depth+1)
	p.scriptScopes = p.scriptScopes[:len(p.scriptScopes)-1]

	if n.Kind == "for_statement" || n.Kind == "for_in_statement" {
		out.children = []*bundleNode{{kind: nodeBranch, span: out.span, children: out.children}}

		if n.Kind == "for_in_statement" {
			b.gap = errors.New("script iterator binding values are unresolved")
			// Do not reuse an outer value as the iterator's assigned value.
			binding := &bundleNode{span: out.span}
			b.scriptBindingWrite(p, n.Child("left"), nil, binding, depth)
			out.children = append([]*bundleNode{binding}, out.children...)
		}
	}

	return out
}

func (b *bundleAnalysis) scriptScopeBindings(p *bundleProgram, nodes []*scriptsyntax.Node, names map[string]bool, depth int) {
	if depth > 64 {
		b.err = errors.New("script block binding depth limit")
		return
	}

	for _, decl := range nodes {
		if !b.step() {
			return
		}

		switch decl.Kind {
		case "lexical_declaration":
			for _, c := range decl.Children {
				if c.Kind == "variable_declarator" {
					b.scriptBindingNames(p, c.Child("name"), names, 0)
				}
			}
		case "function_declaration", "generator_function_declaration", "class_declaration":
			b.scriptBindingNames(p, decl.Child("name"), names, 0)
		case "switch_case", "switch_default":
			b.scriptScopeBindings(p, decl.Children, names, depth+1)
		}
	}
}

func (b *bundleAnalysis) scriptBindingNames(p *bundleProgram, n *scriptsyntax.Node, names map[string]bool, depth int) {
	if n == nil || !b.step() {
		return
	}

	if depth > 64 {
		b.err = errors.New("script binding pattern depth limit")
		return
	}

	switch n.Kind {
	case "identifier", "shorthand_property_identifier_pattern":
		names[scriptText(p, n)] = true
	case "pair_pattern":
		b.scriptBindingNames(p, n.Child("value"), names, depth+1)
	case "assignment_pattern", "object_assignment_pattern":
		b.scriptBindingNames(p, n.Child("left"), names, depth+1)
	case "object_pattern", "array_pattern", "rest_pattern":
		b.gap = errors.New("destructured script block bindings are unresolved")
		for _, c := range n.Children {
			b.scriptBindingNames(p, c, names, depth+1)
		}
	}
}

func (b *bundleAnalysis) scriptCaptures(p *bundleProgram, nodes []*bundleNode, locals map[string]bool, depth int) bool {
	if len(p.scriptScopes) == 0 {
		return false
	}

	if depth > 64 {
		return true
	}

	for _, n := range nodes {
		if n == nil {
			continue
		}

		if !b.step() {
			return true
		}

		if n.kind == nodeName || n.kind == nodeAssign || n.kind == nodeMutate {
			for _, scope := range p.scriptScopes {
				if !locals[n.name] && scope[n.name] {
					return true
				}
			}
		}

		if b.scriptCaptures(p, n.children, locals, depth+1) {
			return true
		}
	}

	return false
}

func (b *bundleAnalysis) scriptFunctionLocals(p *bundleProgram, nodes []*scriptsyntax.Node, names map[string]bool, direct bool, depth int) {
	if depth > 64 {
		b.err = errors.New("script function binding depth limit")
		return
	}

	for _, n := range nodes {
		if !b.step() {
			return
		}

		switch n.Kind {
		case "export_statement":
			b.scriptFunctionLocals(p, n.Children, names, direct, depth+1)
		case "arrow_function", "function_expression", "generator_function", "method_definition", "class":
			continue
		case "function_declaration", "generator_function_declaration", "class_declaration":
			if direct {
				b.scriptBindingNames(p, n.Child("name"), names, 0)
			}
		case "for_in_statement":
			b.scriptIteratorBinding(p, n, names, true)
			b.scriptFunctionLocals(p, n.Children, names, false, depth+1)
		case "lexical_declaration", "variable_declaration":
			if direct || n.Kind == "variable_declaration" {
				for _, decl := range n.Children {
					if decl.Kind == "variable_declarator" {
						b.scriptBindingNames(p, decl.Child("name"), names, 0)
					}
				}
			}
		default:
			b.scriptFunctionLocals(p, n.Children, names, false, depth+1)
		}
	}
}

func (b *bundleAnalysis) scriptIteratorBinding(p *bundleProgram, n *scriptsyntax.Node, names map[string]bool, hoisted bool) {
	for _, c := range n.Children {
		if c.Field == "kind" && (hoisted && c.Kind == "var" || !hoisted && (c.Kind == "let" || c.Kind == "const")) {
			b.scriptBindingNames(p, n.Child("left"), names, 0)
		}
	}
}

func (b *bundleAnalysis) scriptGlobalWrites(nodes []*bundleNode, locals map[string]bool, depth int) {
	if depth > 64 {
		b.err = errors.New("script global write projection depth limit")
		return
	}

	for _, n := range nodes {
		if n == nil {
			continue
		}

		if !b.step() {
			return
		}

		scope := locals
		if n.kind == nodeScope {
			scope = map[string]bool{}
			maps.Copy(scope, locals)
			maps.Copy(scope, n.locals)
		}

		if (n.kind == nodeAssign || n.kind == nodeMutate) && n.name != "" && !scope[n.name] {
			n.globalWrite = true
		}

		if n.kind == nodeWrite {
			n.globalWrite = true
		}

		b.scriptGlobalWrites(n.children, scope, depth+1)
	}
}

func (b *bundleAnalysis) scriptNestedReturn(nodes []*bundleNode, nested bool, depth int) bool {
	if depth > 64 {
		return true
	}

	for _, n := range nodes {
		if n == nil {
			continue
		}

		if !b.step() {
			return true
		}

		if n.kind == nodeReturn && nested {
			return true
		}

		if b.scriptNestedReturn(n.children, nested || n.kind == nodeScope || n.kind == nodeBranch, depth+1) {
			return true
		}
	}

	return false
}

func (b *bundleAnalysis) scriptCollection(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if n.Kind == "object" {
		out.kind = nodeObject
		out.children = b.scriptNodes(p, n.Children, depth+1)
	} else {
		out.kind = nodeArray
		out.children = b.scriptArray(p, n.Children, depth)
	}

	return out
}

func (b *bundleAnalysis) scriptFunctionDeclaration(p *bundleProgram, n *scriptsyntax.Node, depth int, exported bool) {
	if fn := b.scriptFunction(p, n, depth); fn != nil && exported {
		p.exports[fn.name] = fn.name
	}
}

func (b *bundleAnalysis) scriptCallNode(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	out.kind = nodeCall
	if n.Kind == "new_expression" {
		out.kind = nodeConstruct
	}

	out.children = b.scriptCallChildren(p, n, depth)

	return out
}

func (b *bundleAnalysis) scriptMutation(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	left := n.Child("left")
	if left == nil {
		left = n.Child("argument")
	}

	if left != nil && (left.Kind == "member_expression" || left.Kind == "subscript_expression") {
		return b.scriptMemberWrite(p, left, n.Child("right"), out, depth)
	}

	out.kind, out.name = nodeMutate, scriptText(p, n.Child("left"))
	if argument := n.Child("argument"); argument != nil {
		out.name = scriptText(p, argument)
	}

	out.children = []*bundleNode{b.scriptNode(p, n.Child("right"), depth+1, false)}

	return out
}
