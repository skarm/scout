package frontend

import (
	"slices"
	"strings"
)

func (b *pythonNormalizer) assignmentNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	if n.field(pyFieldType) != nil {
		out := b.make(n, AnnAssign)
		b.set(out, Target, childValue(b.node(n.field(pyFieldLeft), depth+1)))
		b.set(out, Annotation, childValue(b.node(n.field(pyFieldType), depth+1)))
		b.set(out, FieldValue, childValue(b.node(n.field(pyFieldRight), depth+1)))

		return out
	}

	out := b.make(n, Assign)
	targets := []*Node{b.node(n.field(pyFieldLeft), depth+1)}

	rhs := n.field(pyFieldRight)
	for rhs != nil && rhs.Kind == pyKindAssignment {
		targets = append(targets, b.node(rhs.field(pyFieldLeft), depth+1))
		rhs = rhs.field(pyFieldRight)
	}

	b.set(out, Targets, nodesValue(targets))
	b.set(out, FieldValue, childValue(b.node(rhs, depth+1)))

	return out
}

func (b *pythonNormalizer) ifNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Test, childValue(b.node(n.field(pyFieldCondition), depth+1)))
	b.set(out, Body, nodesValue(b.list(n.field(pyFieldConsequence), depth)))

	tail := make([]*Node, 0)
	alternatives := make([]*pythonSyntax, 0)

	for _, child := range n.named() {
		if child.Field == pyFieldAlternative {
			alternatives = append(alternatives, child)
		}
	}

	for _, alternative := range slices.Backward(alternatives) {
		if alternative.Kind == pyKindElseClause {
			tail = b.list(alternative.field(pyFieldBody), depth)
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
	b.set(out, Target, childValue(b.node(n.field(pyFieldLeft), depth+1)))
	b.set(out, Iter, childValue(b.node(n.field(pyFieldRight), depth+1)))
	b.set(out, Test, childValue(b.node(n.field(pyFieldCondition), depth+1)))
	b.set(out, Body, nodesValue(b.list(n.field(pyFieldBody), depth)))
	b.set(out, Orelse, nodesValue(b.list(n.field(pyFieldAlternative).field(pyFieldBody), depth)))

	return out
}

func (b *pythonNormalizer) tryNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	clauses := n.named()
	for _, clause := range clauses {
		if clause.Kind == pyKindExceptClause && !plainPythonExcept(clause) {
			return b.unsupportedNode(n, depth)
		}
	}

	out := b.make(n, kind)
	b.set(out, Body, nodesValue(b.list(n.field(pyFieldBody), depth)))

	var handlers, otherwise, final []*Node

	for _, clause := range clauses {
		switch clause.Kind {
		case pyKindExceptClause:
			h := b.make(clause, ExceptHandler)
			test, alias := pythonExceptBinding(clause)
			b.set(h, Test, childValue(b.node(test, depth+1)))
			b.set(h, FieldName, StringValue(b.textOf(alias)))
			b.set(h, Body, nodesValue(b.list(pythonClauseBlock(clause), depth+1)))
			handlers = append(handlers, h)
		case pyKindElseClause:
			otherwise = b.list(clause.field(pyFieldBody), depth)
		case pyKindFinallyClause:
			final = b.list(pythonClauseBlock(clause), depth)
		}
	}

	b.set(out, Handlers, nodesValue(handlers))
	b.set(out, Orelse, nodesValue(otherwise))
	b.set(out, Finalbody, nodesValue(final))

	return out
}

func plainPythonExcept(clause *pythonSyntax) bool {
	_, alias := pythonExceptBinding(clause)
	if alias != nil && alias.Kind != pyKindIdentifier {
		return false
	}

	value := false

	for _, child := range clause.Children {
		if child.Kind == pyKindAsterisk || child.Field == pyFieldValue && value {
			return false
		}

		value = value || child.Field == pyFieldValue
	}

	return true
}

func pythonExceptBinding(clause *pythonSyntax) (test, alias *pythonSyntax) {
	test, alias = clause.field(pyFieldValue), clause.field(pyFieldAlias)
	if test != nil && test.Kind == pyKindAsPattern {
		return test.first(), test.field(pyFieldAlias).first()
	}

	return test, alias
}

func pythonClauseBlock(clause *pythonSyntax) *pythonSyntax {
	for _, child := range clause.Children {
		if child.Kind == pyKindBlock {
			return child
		}
	}

	return nil
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
	if strings.HasSuffix(n.Kind, "statement") || strings.HasSuffix(n.Kind, "definition") || n.Kind == pyKindMatchStatement {
		typ = UnsupportedStatement
	}

	out := b.make(n, typ)
	b.set(out, Body, nodesValue(b.list(n, depth)))

	return out
}

func (b *pythonNormalizer) expressionStatement(n *pythonSyntax, depth int, kind NodeKind) *Node {
	xs := n.named()
	if len(xs) == 1 && (xs[0].Kind == pyKindAssignment || xs[0].Kind == pyKindAugmentedAssignment) {
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
		if x.Kind == pyKindWithClause {
			for _, item := range x.named() {
				value := item.field(pyFieldValue)

				wi := b.make(item, WithItem)
				if value != nil && value.Kind == pyKindAsPattern {
					b.set(wi, ContextExpr, childValue(b.node(value.first(), depth+1)))
					b.set(wi, OptionalVars, childValue(b.node(value.field(pyFieldAlias), depth+1)))
				} else {
					b.set(wi, ContextExpr, childValue(b.node(value, depth+1)))
				}

				items = append(items, wi)
			}
		}
	}

	b.set(out, Items, nodesValue(items))
	b.set(out, Body, nodesValue(b.list(n.field(pyFieldBody), depth)))

	return out
}
