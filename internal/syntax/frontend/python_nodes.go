package frontend

import (
	"strings"
)

func (b *pythonNormalizer) importNode(n *pythonSyntax, _ int, typ NodeKind) *Node {
	out := b.make(n, typ)
	names := make([]*Node, 0)

	for _, x := range n.named() {
		if x.Field == "module_name" {
			continue
		}

		if x.Kind == "dotted_name" || x.Kind == "aliased_import" || x.Kind == "wildcard_import" {
			names = append(names, b.alias(x))
		}
	}

	b.set(out, Names, nodesValue(names))

	if typ == ImportFrom {
		module := b.textOf(n.field("module_name"))
		if n.Kind == "future_import_statement" {
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
	b.set(out, Func, childValue(b.node(n.field("function"), depth+1)))

	args, keywords := make([]*Node, 0), make([]*Node, 0)

	for _, x := range n.field("arguments").named() {
		switch x.Kind {
		case "keyword_argument":
			k := b.make(x, Keyword)
			b.set(k, FieldArg, StringValue(b.textOf(x.field("name"))))
			b.set(k, FieldValue, childValue(b.node(x.field("value"), depth+1)))
			keywords = append(keywords, k)
		case "dictionary_splat":
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
