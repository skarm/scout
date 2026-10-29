package frontend

import (
	"slices"
	"strings"
)

func (b *pythonNormalizer) assignmentNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	if n.field("type") != nil {
		out := b.make(n, AnnAssign)
		b.set(out, Target, childValue(b.node(n.field("left"), depth+1)))
		b.set(out, Annotation, childValue(b.node(n.field("type"), depth+1)))
		b.set(out, FieldValue, childValue(b.node(n.field("right"), depth+1)))

		return out
	}

	out := b.make(n, Assign)
	targets := []*Node{b.node(n.field("left"), depth+1)}

	rhs := n.field("right")
	for rhs != nil && rhs.Kind == "assignment" {
		targets = append(targets, b.node(rhs.field("left"), depth+1))
		rhs = rhs.field("right")
	}

	b.set(out, Targets, nodesValue(targets))
	b.set(out, FieldValue, childValue(b.node(rhs, depth+1)))

	return out
}

func (b *pythonNormalizer) ifNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Test, childValue(b.node(n.field("condition"), depth+1)))
	b.set(out, Body, nodesValue(b.list(n.field("consequence"), depth)))

	tail := make([]*Node, 0)
	alternatives := make([]*pythonSyntax, 0)

	for _, child := range n.named() {
		if child.Field == "alternative" {
			alternatives = append(alternatives, child)
		}
	}

	for _, alternative := range slices.Backward(alternatives) {
		if alternative.Kind == "else_clause" {
			tail = b.list(alternative.field("body"), depth)
		} else {
			next := b.node(alternative, depth+1)
			b.set(next, Orelse, nodesValue(tail))
			tail = []*Node{next}
		}
	}

	b.set(out, Orelse, nodesValue(tail))

	return out
}

func (b *pythonNormalizer) loopNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Target, childValue(b.node(n.field("left"), depth+1)))
	b.set(out, Iter, childValue(b.node(n.field("right"), depth+1)))
	b.set(out, Test, childValue(b.node(n.field("condition"), depth+1)))
	b.set(out, Body, nodesValue(b.list(n.field("body"), depth)))
	b.set(out, Orelse, nodesValue(b.list(n.field("alternative").field("body"), depth)))

	return out
}

func (b *pythonNormalizer) nameDeclarationNode(n *pythonSyntax, _ int, kind NodeKind) *Node {
	out := b.make(n, kind)

	children := n.named()

	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, b.textOf(child))
	}

	b.set(out, Names, stringsValue(names))

	return out
}

func (b *pythonNormalizer) unsupportedNode(n *pythonSyntax, depth int) *Node {
	// Preserve traversable descendants but explicitly mark projection gaps.
	// Unknown statements are state barriers in the Go security analyzer.
	b.partial = true

	typ := UnsupportedExpression
	if strings.HasSuffix(n.Kind, "statement") || strings.HasSuffix(n.Kind, "definition") || n.Kind == "match_statement" {
		typ = UnsupportedStatement
	}

	out := b.make(n, typ)
	b.set(out, Body, nodesValue(b.list(n, depth)))

	return out
}

func (b *pythonNormalizer) expressionStatement(n *pythonSyntax, depth int, kind NodeKind) *Node {
	xs := n.named()
	if len(xs) == 1 && (xs[0].Kind == "assignment" || xs[0].Kind == "augmented_assignment") {
		return b.node(xs[0], depth+1)
	}

	out := b.make(n, kind)
	if len(xs) == 1 {
		b.set(out, FieldValue, childValue(b.node(xs[0], depth+1)))
	} else {
		b.partial = true
		out.kind = UnsupportedStatement
		b.set(out, Body, nodesValue(b.list(n, depth)))
	}

	return out
}

func (b *pythonNormalizer) withNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	items := make([]*Node, 0)

	for _, x := range n.named() {
		if x.Kind == "with_clause" {
			for _, item := range x.named() {
				value := item.field("value")

				wi := b.make(item, WithItem)
				if value != nil && value.Kind == "as_pattern" {
					b.set(wi, ContextExpr, childValue(b.node(value.first(), depth+1)))
					b.set(wi, OptionalVars, childValue(b.node(value.field("alias"), depth+1)))
				} else {
					b.set(wi, ContextExpr, childValue(b.node(value, depth+1)))
				}

				items = append(items, wi)
			}
		}
	}

	b.set(out, Items, nodesValue(items))
	b.set(out, Body, nodesValue(b.list(n.field("body"), depth)))

	return out
}
