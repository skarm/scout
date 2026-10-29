package frontend

import "strings"

func (b *pythonNormalizer) typeNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	// Grammar wrappers preserve annotations without inferring host timing.
	if len(n.named()) == 1 {
		return b.node(n.first(), depth+1)
	}

	b.partial = true
	out := b.make(n, UnsupportedExpression)
	b.set(out, Body, nodesValue(b.list(n, depth)))

	return out
}

func (b *pythonNormalizer) stringNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	if value, bytesValue, ok := pythonLiteral(b.textOf(n)); ok {
		out := b.make(n, Constant)
		if bytesValue {
			b.set(out, FieldValue, BytesValue([]byte(value)))
		} else {
			b.set(out, FieldValue, StringValue(value))
		}

		return out
	}

	return b.interpolatedString(n, depth)
}

func (b *pythonNormalizer) concatenatedStringNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	parts := b.list(n, depth)
	if value, ok := concatenatedLiteral(parts); ok {
		out := b.make(n, Constant)
		b.set(out, FieldValue, StringValue(value))

		return out
	}

	out := b.make(n, JoinedStr)
	b.set(out, Values, nodesValue(parts))

	return out
}

func (b *pythonNormalizer) dictionaryNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	var (
		keys []*Node
		vals []*Node
	)

	out := b.make(n, kind)

	for _, x := range n.named() {
		if x.Kind == "pair" {
			keys = append(keys, b.node(x.field("key"), depth+1))
			vals = append(vals, b.node(x.field("value"), depth+1))
		} else {
			keys = append(keys, nil)
			vals = append(vals, b.node(x.first(), depth+1))
		}
	}

	b.set(out, Keys, nodesValue(keys))
	b.set(out, Values, nodesValue(vals))

	return out
}

func (b *pythonNormalizer) booleanNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Values, nodesValue([]*Node{b.node(n.field("left"), depth+1), b.node(n.field("right"), depth+1)}))

	if op := pythonBooleanOperator(n); op != "" {
		b.set(out, Op, StringValue(op))
	}

	return out
}

func (b *pythonNormalizer) conditionalNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	parts := n.named()
	if len(parts) != 3 {
		return b.unsupportedNode(n, depth)
	}

	out := b.make(n, kind)
	b.set(out, Body, childValue(b.node(parts[0], depth+1)))
	b.set(out, Test, childValue(b.node(parts[1], depth+1)))
	b.set(out, Orelse, childValue(b.node(parts[2], depth+1)))

	return out
}

func (b *pythonNormalizer) unaryNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Operand, childValue(b.node(n.field("argument"), depth+1)))

	if op := pythonUnaryOperator(b.textOf(n)); op != "" {
		b.set(out, Op, StringValue(op))
	}

	return out
}

func (b *pythonNormalizer) decoratedNode(n *pythonSyntax, depth int, _ NodeKind) *Node {
	out := b.node(n.field("definition"), depth+1)
	decorators := make([]*Node, 0)

	for _, child := range n.named() {
		if child.Kind == "decorator" {
			decorators = append(decorators, b.node(child.first(), depth+1))
		}
	}

	b.set(out, DecoratorList, nodesValue(decorators))

	return out
}

func (b *pythonNormalizer) lambdaNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Args, childValue(b.parameters(n.field("parameters"), depth+1)))
	b.set(out, Body, childValue(b.node(n.field("body"), depth+1)))

	return out
}

func (b *pythonNormalizer) comprehensionNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)

	generators := make([]*Node, 0)
	for _, x := range n.named() {
		if x.Kind == "for_in_clause" {
			g := b.make(x, comprehension)
			b.set(g, Target, childValue(b.node(x.field("left"), depth+1)))
			b.set(g, Iter, childValue(b.node(x.field("right"), depth+1)))
			generators = append(generators, g)
		} else if x.Kind == "if_clause" && len(generators) > 0 {
			g := generators[len(generators)-1]
			b.set(g, Ifs, nodesValue(append(g.List(Ifs), b.node(x.first(), depth+1))))
		}
	}

	b.set(out, Generators, nodesValue(generators))

	if kind == DictComp {
		b.set(out, Key, childValue(b.node(n.field("body").field("key"), depth+1)))
		b.set(out, FieldValue, childValue(b.node(n.field("body").field("value"), depth+1)))
	} else {
		b.set(out, Elt, childValue(b.node(n.field("body"), depth+1)))
	}

	return out
}

func (b *pythonNormalizer) interpolatedString(n *pythonSyntax, depth int) *Node {
	out := b.make(n, JoinedStr)
	values := make([]*Node, 0)

	for _, x := range n.named() {
		if x.Kind == "interpolation" {
			values = append(values, b.node(x, depth+1))
		}
	}

	if len(values) == 0 {
		b.partial = true
		out.kind = UnsupportedExpression
	}

	b.set(out, Values, nodesValue(values))

	return out
}

func concatenatedLiteral(parts []*Node) (string, bool) {
	var value strings.Builder

	for _, p := range parts {
		if p == nil || p.Kind() != Constant {
			return "", false
		}

		text, ok := p.Field(FieldValue).Text()
		if !ok {
			return "", false
		}

		value.WriteString(text)
	}

	return value.String(), true
}

func pythonUnaryOperator(text string) string {
	op := strings.TrimSpace(text)
	for _, entry := range []struct{ token, name string }{{token: "not", name: "Not"}, {token: "-", name: "USub"}, {
		token: "+",
		name:  "UAdd",
	}, {
		token: "~",
		name:  "Invert",
	}} {
		if strings.HasPrefix(op, entry.token) {
			return entry.name
		}
	}

	return ""
}

func pythonBooleanOperator(n *pythonSyntax) string {
	op := ""

	for _, token := range n.Children {
		if name := map[string]string{"and": "And", "or": "Or"}[token.Kind]; name != "" {
			op = name
		}
	}

	return op
}
