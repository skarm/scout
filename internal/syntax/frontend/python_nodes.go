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

	args, keywords := make([]*Node, 0), make([]*Node, 0)

	for _, x := range n.field(pyFieldArguments).named() {
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
