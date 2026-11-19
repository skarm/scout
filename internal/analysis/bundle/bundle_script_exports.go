package bundle

import (
	"errors"
	"strings"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func (b *bundleAnalysis) scriptExport(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	if n.Child(scriptsyntax.FieldSource) != nil {
		b.gap = errors.New("script bundle re-exports are unresolved")
		return nil
	}

	defaultExport := false
	for _, c := range n.Children {
		defaultExport = defaultExport || c.Kind == scriptsyntax.KindDefault
		if c.Kind == scriptsyntax.KindExportClause {
			for _, spec := range c.Children {
				if spec.Kind != scriptsyntax.KindExportSpecifier {
					continue
				}

				name := scriptText(p, spec.Child(scriptsyntax.FieldName))
				alias := scriptText(p, spec.Child(scriptsyntax.FieldAlias))

				if alias == "" {
					alias = name
				}

				p.exports[alias] = name
			}

			return nil
		}
	}

	if decl := n.Child(scriptsyntax.FieldDeclaration); decl != nil {
		if !defaultExport {
			return b.scriptNode(p, decl, depth+1, true)
		}

		if decl.Kind == scriptsyntax.KindFunctionDeclaration {
			if fn := b.scriptFunction(p, decl, depth+1); fn != nil {
				p.exports["default"] = fn.name
			}

			return nil
		}
	}

	if value := n.Child(scriptsyntax.FieldValue); defaultExport && value != nil {
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
	if name != nil && name.Kind == scriptsyntax.KindIdentifier {
		binding := scriptText(p, name)
		p.exports[binding] = binding
	} else {
		b.gap = errors.New("destructured script exports are unresolved")
	}
}

func (b *bundleAnalysis) scriptValue(p *bundleProgram, n *scriptsyntax.Node, depth int) *bundleNode {
	for _, c := range n.Children {
		switch c.Kind {
		case scriptsyntax.KindOpenParen, scriptsyntax.KindCloseParen, scriptsyntax.KindAwait, scriptsyntax.KindReturn, scriptsyntax.KindSemicolon, scriptsyntax.KindComment, scriptsyntax.KindAs, scriptsyntax.KindSatisfies, scriptsyntax.KindBang, scriptsyntax.KindTypeArguments:
			continue
		default:
			return b.scriptNode(p, c, depth+1, false)
		}
	}

	return nil
}

func (b *bundleAnalysis) scriptCallChildren(p *bundleProgram, n *scriptsyntax.Node, depth int) []*bundleNode {
	callee := n.Child(scriptsyntax.FieldFunction)
	if callee == nil {
		callee = n.Child(scriptsyntax.FieldConstructor)
	}

	out := []*bundleNode{b.scriptNode(p, callee, depth+1, false)}

	if args := n.Child(scriptsyntax.FieldArguments); args != nil {
		for _, c := range args.Children {
			if c.Kind == scriptsyntax.KindSpreadElement {
				b.gap = errors.New("spread script bundle arguments are unresolved")
				// Preserve observations in argument expressions, but do not bind
				// an unknown argument sequence to fixed parameter positions.
				out[0] = nil
			}

			if c.Kind != scriptsyntax.KindOpenParen && c.Kind != scriptsyntax.KindCloseParen && c.Kind != scriptsyntax.KindComma && c.Kind != scriptsyntax.KindComment {
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

		if n.Kind == scriptsyntax.KindVariableDeclaration && c.Kind == scriptsyntax.KindVariableDeclarator && c.Child(scriptsyntax.FieldValue) == nil {
			v.kind = nodeDeclare
		}

		out = append(out, v)
	}

	return out
}

func (b *bundleAnalysis) scriptScope(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	out.kind, out.locals = nodeScope, map[string]bool{}
	b.scriptBindingNames(p, n.Child(scriptsyntax.FieldParameter), out.locals, 0)

	if n.Kind == scriptsyntax.KindForInStatement {
		b.scriptIteratorBinding(p, n, out.locals, false)
	}

	b.scriptScopeBindings(p, n.Children, out.locals, 0)

	p.scriptScopes = append(p.scriptScopes, out.locals)
	out.children = b.scriptNodes(p, n.Children, depth+1)
	p.scriptScopes = p.scriptScopes[:len(p.scriptScopes)-1]

	if n.Kind == scriptsyntax.KindForStatement || n.Kind == scriptsyntax.KindForInStatement {
		out.children = []*bundleNode{{kind: nodeBranch, span: out.span, children: out.children}}

		if n.Kind == scriptsyntax.KindForInStatement {
			b.gap = errors.New("script iterator binding values are unresolved")
			// Do not reuse an outer value as the iterator's assigned value.
			binding := &bundleNode{span: out.span}
			b.scriptBindingWrite(p, n.Child(scriptsyntax.FieldLeft), nil, binding, depth)
			out.children = append([]*bundleNode{binding}, out.children...)
		}
	}

	return out
}

func (b *bundleAnalysis) scriptScopeBindings(p *bundleProgram, nodes []*scriptsyntax.Node, names map[string]bool, depth int) {
	if depth > maxBundleProjectionDepth {
		b.err = errors.New("script block binding depth limit")
		return
	}

	for _, decl := range nodes {
		if !b.step() {
			return
		}

		switch decl.Kind {
		case scriptsyntax.KindLexicalDeclaration:
			for _, c := range decl.Children {
				if c.Kind == scriptsyntax.KindVariableDeclarator {
					b.scriptBindingNames(p, c.Child(scriptsyntax.FieldName), names, 0)
				}
			}
		case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindClassDeclaration:
			b.scriptBindingNames(p, decl.Child(scriptsyntax.FieldName), names, 0)
		case scriptsyntax.KindSwitchCase, scriptsyntax.KindSwitchDefault:
			b.scriptScopeBindings(p, decl.Children, names, depth+1)
		}
	}
}

func (b *bundleAnalysis) scriptBindingNames(p *bundleProgram, n *scriptsyntax.Node, names map[string]bool, depth int) {
	if n == nil || !b.step() {
		return
	}

	if depth > maxBundleProjectionDepth {
		b.err = errors.New("script binding pattern depth limit")
		return
	}

	switch n.Kind {
	case scriptsyntax.KindIdentifier, scriptsyntax.KindShorthandPropertyIdentifierPattern:
		names[scriptText(p, n)] = true
	case scriptsyntax.KindPairPattern:
		b.scriptBindingNames(p, n.Child(scriptsyntax.FieldValue), names, depth+1)
	case scriptsyntax.KindAssignmentPattern, scriptsyntax.KindObjectAssignmentPattern:
		b.scriptBindingNames(p, n.Child(scriptsyntax.FieldLeft), names, depth+1)
	case scriptsyntax.KindObjectPattern, scriptsyntax.KindArrayPattern, scriptsyntax.KindRestPattern:
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

	if depth > maxBundleProjectionDepth {
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
	if depth > maxBundleProjectionDepth {
		b.err = errors.New("script function binding depth limit")
		return
	}

	for _, n := range nodes {
		if !b.step() {
			return
		}

		switch n.Kind {
		case scriptsyntax.KindExportStatement:
			b.scriptFunctionLocals(p, n.Children, names, direct, depth+1)
		case scriptsyntax.KindArrowFunction, scriptsyntax.KindFunctionExpression, scriptsyntax.KindGeneratorFunction, scriptsyntax.KindMethodDefinition, scriptsyntax.KindClass:
			continue
		case scriptsyntax.KindFunctionDeclaration, scriptsyntax.KindGeneratorFunctionDeclaration, scriptsyntax.KindClassDeclaration:
			if direct {
				b.scriptBindingNames(p, n.Child(scriptsyntax.FieldName), names, 0)
			}
		case scriptsyntax.KindForInStatement:
			b.scriptIteratorBinding(p, n, names, true)
			b.scriptFunctionLocals(p, n.Children, names, false, depth+1)
		case scriptsyntax.KindLexicalDeclaration, scriptsyntax.KindVariableDeclaration:
			if direct || n.Kind == scriptsyntax.KindVariableDeclaration {
				for _, decl := range n.Children {
					if decl.Kind == scriptsyntax.KindVariableDeclarator {
						b.scriptBindingNames(p, decl.Child(scriptsyntax.FieldName), names, 0)
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
		if c.Field == scriptsyntax.FieldKind && (hoisted && c.Kind == scriptsyntax.KindVar || !hoisted && (c.Kind == scriptsyntax.KindLet || c.Kind == scriptsyntax.KindConst)) {
			b.scriptBindingNames(p, n.Child(scriptsyntax.FieldLeft), names, 0)
		}
	}
}

func (b *bundleAnalysis) scriptGlobalWrites(nodes []*bundleNode, locals map[string]bool, depth int) {
	if depth > maxBundleProjectionDepth {
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
			if !copyBundleEntries(b, scope, locals) || !copyBundleEntries(b, scope, n.locals) {
				return
			}
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
	if depth > maxBundleProjectionDepth {
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
	if n.Kind == scriptsyntax.KindObject {
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
	if n.Kind == scriptsyntax.KindNewExpression {
		out.kind = nodeConstruct
	}

	out.children = b.scriptCallChildren(p, n, depth)

	return out
}

func (b *bundleAnalysis) scriptMutation(p *bundleProgram, n *scriptsyntax.Node, out *bundleNode, depth int) *bundleNode {
	left := n.Child(scriptsyntax.FieldLeft)
	if left == nil {
		left = n.Child(scriptsyntax.FieldArgument)
	}

	if left != nil && (left.Kind == scriptsyntax.KindMemberExpression || left.Kind == scriptsyntax.KindSubscriptExpression) {
		return b.scriptMemberWrite(p, left, n.Child(scriptsyntax.FieldRight), out, depth)
	}

	op := strings.TrimSuffix(scriptText(p, n.Child(scriptsyntax.FieldOperator)), "=")
	if left != nil && left.Kind == scriptsyntax.KindIdentifier && scriptBinaryKind(op) == nodeScalar {
		out.kind, out.name = nodeAssign, scriptText(p, left)
		result := &bundleNode{kind: nodeScalar, span: out.span, children: []*bundleNode{b.scriptNode(p, left, depth+1, false)}}

		if right := n.Child(scriptsyntax.FieldRight); right != nil {
			result.children = append(result.children, b.scriptNode(p, right, depth+1, false))
		}

		out.children = []*bundleNode{result}

		return out
	}

	out.kind, out.name = nodeMutate, scriptText(p, n.Child(scriptsyntax.FieldLeft))
	if argument := n.Child(scriptsyntax.FieldArgument); argument != nil {
		out.name = scriptText(p, argument)
	}

	out.children = []*bundleNode{b.scriptNode(p, n.Child(scriptsyntax.FieldRight), depth+1, false)}

	return out
}
