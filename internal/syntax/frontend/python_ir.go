package frontend

import (
	"context"
)

// pythonSyntax is a bounded, byte-addressed copy of Tree-sitter's CST. This is
// only a normalizer input, NOT a hand-written parser or a CPython AST claim.
type pythonSyntax struct {
	Kind, Field string
	Start, End  int
	Named       bool
	Children    []*pythonSyntax
}

type pythonNormalizer struct {
	ctx            context.Context
	text           string
	nodes, encoded int
	partial        bool
	err            error
}

func normalizePython(ctx context.Context, text string, root *pythonSyntax) (*Node, error) {
	n := &pythonNormalizer{ctx: ctx, text: text}

	if root == nil || root.Kind != "module" {
		return nil, &Failure{Category: "invalid_tree"}
	}

	ast := n.node(root, 0)
	if n.err != nil {
		return nil, n.err
	}

	if n.partial {
		return ast, &Failure{Category: "unsupported_projection"}
	}

	return ast, nil
}

func (n *pythonSyntax) field(key string) *pythonSyntax {
	if n != nil {
		for _, x := range n.Children {
			if x.Field == key {
				return x
			}
		}
	}

	return nil
}

func (n *pythonSyntax) named() []*pythonSyntax {
	var out []*pythonSyntax

	if n != nil {
		for _, x := range n.Children {
			if x.Named && x.Kind != "comment" {
				out = append(out, x)
			}
		}
	}

	return out
}

func (n *pythonSyntax) first() *pythonSyntax {
	for _, x := range n.named() {
		return x
	}

	return nil
}

func (b *pythonNormalizer) textOf(n *pythonSyntax) string {
	if n == nil || n.Start < 0 || n.End < n.Start || n.End > len(b.text) {
		return ""
	}

	return b.text[n.Start:n.End]
}

func (b *pythonNormalizer) make(n *pythonSyntax, typ NodeKind) *Node {
	b.nodes++
	if b.nodes > maxNodes {
		b.err = &Failure{Category: "limit"}
	}

	return newNode(typ, n.Start, n.End)
}

func (b *pythonNormalizer) set(n *Node, key FieldKind, value Value) {
	if b.err != nil || n == nil {
		return
	}

	size := value.encodedSize()

	b.encoded += size
	if b.encoded > maxOutput {
		b.err = &Failure{Category: "output_limit"}
		return
	}

	if err := n.set(Field{kind: key, value: value}); err != nil {
		b.err = &Failure{Category: "invalid_tree"}
	}
}

func (b *pythonNormalizer) list(n *pythonSyntax, depth int) []*Node {
	out := make([]*Node, 0)

	for _, x := range n.named() {
		if v := b.node(x, depth+1); v != nil {
			out = append(out, v)
		}
	}

	return out
}

func (b *pythonNormalizer) alias(n *pythonSyntax) *Node {
	out := b.make(n, Alias)

	name, asname := b.textOf(n), ""
	if n.Kind == "aliased_import" {
		name = b.textOf(n.field("name"))
		asname = b.textOf(n.field("alias"))
	}

	if n.Kind == "wildcard_import" {
		name = "*"
	}

	b.set(out, FieldName, StringValue(name))
	b.set(out, Asname, StringValue(asname))

	return out
}

func (b *pythonNormalizer) node(n *pythonSyntax, depth int) *Node {
	if n == nil || !b.accept(n, depth) {
		return nil
	}

	projection, supported := pythonProjections[n.Kind]
	if !supported {
		return b.unsupportedNode(n, depth)
	}

	if projection.build != nil {
		return projection.build(b, n, depth, projection.kind)
	}

	return b.projectFields(n, depth, projection)
}

func (b *pythonNormalizer) accept(n *pythonSyntax, depth int) bool {
	if b.err != nil {
		return false
	}

	if depth > MaxDepth || n.Start < 0 || n.End < n.Start || n.End > len(b.text) {
		b.err = &Failure{Category: "limit"}
		return false
	}

	if b.ctx.Err() != nil {
		b.err = &Failure{Category: "deadline"}
		return false
	}

	return n.Kind != "comment"
}
