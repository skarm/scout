package jsonconfig

import (
	"context"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"

	"go.yaml.in/yaml/v4"
)

// KindExpression marks a Cordis !!js scalar. The expression is never evaluated
// or treated as a literal configuration value.
const KindExpression = "expression"

// ParseCordisYAML projects one bounded YAML document. Node ends are
// conservative bounds from the next YAML node or the enclosing document.
func ParseCordisYAML(ctx context.Context, text string) (*Node, error) {
	if ctx == nil {
		return nil, &Error{Code: codeNilContext}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(text) > MaxBytes {
		return nil, &Error{Code: codeByteLimit}
	}

	if !utf8.ValidString(text) {
		return nil, &Error{Code: codeInvalidUnicode}
	}

	d := yaml.NewDecoder(strings.NewReader(text))

	var doc yaml.Node
	if err := d.Decode(&doc); errors.Is(err, io.EOF) {
		return &Node{Kind: KindNull, Span: source.Span{End: len(text)}}, nil
	} else if err != nil || len(doc.Content) != 1 {
		return nil, &Error{Code: valueSyntaxError}
	}

	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &Error{Code: codeTrailingData}
	}

	p := cordisProjection{ctx: ctx}
	p.index(text)

	return p.node(doc.Content[0], len(text), 0)
}

// yaml marks positions in Unicode characters and ignores the stream BOM.
type cordisProjection struct {
	ctx            context.Context
	offsets, lines []int
	nodes          int
}

func (p *cordisProjection) index(text string) {
	start := 0
	if strings.HasPrefix(text, "\ufeff") {
		start = len("\ufeff")
	}

	p.offsets = make([]int, 0, len(text)-start+1)
	p.lines = []int{0}

	for i, r := range text[start:] {
		at := start + i
		p.offsets = append(p.offsets, at)

		switch r {
		case '\r':
			if at+1 < len(text) && text[at+1] == '\n' {
				continue
			}

			p.lines = append(p.lines, len(p.offsets))
		case '\n', '\u0085', '\u2028', '\u2029':
			p.lines = append(p.lines, len(p.offsets))
		}
	}

	p.offsets = append(p.offsets, len(text))
}

func (p *cordisProjection) offset(n *yaml.Node) int {
	if n.Line < 1 || n.Line > len(p.lines) || n.Column < 1 {
		return -1
	}

	index := p.lines[n.Line-1] + n.Column - 1
	if index >= len(p.offsets) || n.Line < len(p.lines) && index >= p.lines[n.Line] {
		return -1
	}

	return p.offsets[index]
}

func (p *cordisProjection) node(n *yaml.Node, end, depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, &Error{Code: codeDepthLimit}
	}

	p.nodes++
	if p.nodes > MaxNodes {
		return nil, &Error{Code: codeNodeLimit}
	}

	if err := p.ctx.Err(); err != nil {
		return nil, err
	}

	start := p.offset(n)
	if start < 0 || start > end {
		return nil, &Error{Code: codeInvalidSpan}
	}

	out := &Node{Span: source.Span{Start: start, End: end}}

	switch {
	case n.Kind == yaml.MappingNode && n.ShortTag() == "!!map":
		return p.mapping(out, n, depth)
	case n.Kind == yaml.SequenceNode && n.ShortTag() == "!!seq":
		out.Kind = KindArray

		for i, item := range n.Content {
			child, err := p.node(item, p.next(n.Content, i+1, end), depth+1)
			if err != nil {
				return nil, err
			}

			out.Elements = append(out.Elements, child)
		}
	case n.Kind == yaml.ScalarNode:
		if !cordisScalar(out, n) {
			return nil, &Error{Code: valueSyntaxError}
		}
	default:
		return nil, &Error{Code: valueSyntaxError}
	}

	return out, nil
}

func (p *cordisProjection) next(nodes []*yaml.Node, index, end int) int {
	if index < len(nodes) {
		return p.offset(nodes[index])
	}

	return end
}

func (p *cordisProjection) mapping(out *Node, n *yaml.Node, depth int) (*Node, error) {
	out.Kind = KindObject

	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Value == "<<" || seen[key.Value] {
			return nil, &Error{Code: CodeDuplicateKey}
		}

		seen[key.Value] = true
		p.nodes++

		child, err := p.node(value, p.next(n.Content, i+2, out.Span.End), depth+1)
		if err != nil {
			return nil, err
		}

		out.Members = append(out.Members, Member{
			Key: key.Value, KeySpan: source.Span{Start: p.offset(key), End: child.Span.Start}, Value: child,
		})
	}

	return out, nil
}

func cordisScalar(out *Node, n *yaml.Node) bool {
	switch n.ShortTag() {
	case "!!str", "!!timestamp":
		out.Kind, out.String = KindString, n.Value
	case "!!bool":
		out.Kind, out.Bool = KindBool, strings.EqualFold(n.Value, "true")
	case "!!null":
		out.Kind = KindNull
	case "!!int", "!!float":
		out.Kind, out.String = KindNumber, n.Value
	case "!!js":
		out.Kind = KindExpression
	default:
		return false
	}

	return true
}
