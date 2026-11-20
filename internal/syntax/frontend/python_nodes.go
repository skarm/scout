package frontend

import (
	"strings"
)

func (b *pythonNormalizer) importNode(n *pythonSyntax, _ int, typ NodeKind) *Node {
	out := b.make(n, typ)
	names := make([]*Node, 0)

	for _, x := range n.named() {
		if x.Field == pyFieldModuleName {
			continue
		}

		if x.Kind == pyKindDottedName || x.Kind == pyKindAliasedImport || x.Kind == pyKindWildcardImport {
			names = append(names, b.alias(x))
		}
	}

	b.set(out, Names, nodesValue(names))

	if typ == ImportFrom {
		module := b.textOf(n.field(pyFieldModuleName))
		if n.Kind == pyKindFutureImportStatement {
			module = "__future__"
		}

		level := len(module) - len(strings.TrimLeft(module, "."))
		b.set(out, FieldModule, StringValue(strings.TrimLeft(module, ".")))
		b.set(out, Level, integerValue(int64(level)))
	}

	return out
}

func (b *pythonNormalizer) callNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, Func, childValue(b.node(n.field(pyFieldFunction), depth+1)))

	arguments := n.field(pyFieldArguments)
	if arguments != nil && arguments.Kind == pyKindGeneratorExpression {
		b.set(out, Args, nodesValue([]*Node{b.node(arguments, depth+1)}))
		b.set(out, Keywords, nodesValue(nil))

		return out
	}

	args, keywords := make([]*Node, 0), make([]*Node, 0)

	for _, x := range arguments.named() {
		switch x.Kind {
		case pyKindKeywordArgument:
			k := b.make(x, Keyword)
			b.set(k, FieldArg, StringValue(b.textOf(x.field(pyFieldName))))
			b.set(k, FieldValue, childValue(b.node(x.field(pyFieldValue), depth+1)))
			keywords = append(keywords, k)
		case pyKindDictionarySplat:
			k := b.make(x, Keyword)
			b.set(k, FieldArg, NullValue())
			b.set(k, FieldValue, childValue(b.node(x.first(), depth+1)))
			keywords = append(keywords, k)
		default:
			args = append(args, b.node(x, depth+1))
		}
	}

	b.set(out, Args, nodesValue(args))
	b.set(out, Keywords, nodesValue(keywords))

	return out
}

func (b *pythonNormalizer) subscriptNode(n *pythonSyntax, depth int, kind NodeKind) *Node {
	out := b.make(n, kind)
	b.set(out, FieldValue, childValue(b.node(n.field(pyFieldValue), depth+1)))
	b.set(out, Slice, childValue(b.subscriptKey(n, depth+1)))

	return out
}

func (b *pythonNormalizer) subscriptKey(n *pythonSyntax, depth int) *Node {
	var indices []*pythonSyntax

	end, comma := 0, false

	for _, child := range n.Children {
		switch {
		case child.Field == pyFieldSubscript:
			indices = append(indices, child)
			end = child.End
		case child.Kind == ",":
			comma = true
			end = child.End
		}
	}

	if len(indices) == 0 {
		return nil
	}

	if len(indices) == 1 && !comma {
		return b.node(indices[0], depth)
	}

	// A comma makes the key a tuple, including a single item followed by a comma.
	tuple := b.make(&pythonSyntax{Start: indices[0].Start, End: end}, Tuple)

	items := make([]*Node, 0, len(indices))
	for _, index := range indices {
		items = append(items, b.node(index, depth+1))
	}

	b.set(tuple, Elts, nodesValue(items))

	return tuple
}
