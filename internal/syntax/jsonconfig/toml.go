package jsonconfig

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"

	"github.com/pelletier/go-toml/v2"
)

// ParseTOML validates duplicate keys and grammar with go-toml. Its projection
// uses the whole source span because the decoder does not expose token positions.
func ParseTOML(ctx context.Context, text string) (*Node, error) {
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

	var values map[string]any
	if err := toml.Unmarshal([]byte(text), &values); err != nil {
		return nil, &Error{Code: valueSyntaxError}
	}

	r := tomlProjection{ctx: ctx, span: source.Span{End: len(text)}}

	return r.node(values, 0)
}

type tomlProjection struct {
	ctx   context.Context
	span  source.Span
	nodes int
}

func (r *tomlProjection) charge() error {
	r.nodes++
	if r.nodes > MaxNodes {
		return &Error{Code: codeNodeLimit}
	}

	return r.ctx.Err()
}

func (r *tomlProjection) node(value any, depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, &Error{Code: codeDepthLimit}
	}

	if err := r.charge(); err != nil {
		return nil, err
	}

	n := &Node{Span: r.span}

	switch v := value.(type) {
	case map[string]any:
		return r.object(n, v, depth)
	case []any:
		n.Kind = KindArray

		for _, item := range v {
			child, err := r.node(item, depth+1)
			if err != nil {
				return nil, err
			}

			n.Elements = append(n.Elements, child)
		}
	case string:
		n.Kind, n.String = KindString, v
	case bool:
		n.Kind, n.Bool = KindBool, v
	case int64, uint64, float64:
		n.Kind, n.String = KindNumber, fmt.Sprint(v)
	case time.Time:
		n.Kind, n.String = KindString, v.Format(time.RFC3339Nano)
	case toml.LocalDate, toml.LocalDateTime, toml.LocalTime:
		n.Kind, n.String = KindString, fmt.Sprint(v)
	default:
		return nil, &Error{Code: valueSyntaxError}
	}

	return n, nil
}

func (r *tomlProjection) object(n *Node, values map[string]any, depth int) (*Node, error) {
	n.Kind = KindObject

	for _, key := range slices.Sorted(maps.Keys(values)) {
		if err := r.charge(); err != nil {
			return nil, err
		}

		child, err := r.node(values[key], depth+1)
		if err != nil {
			return nil, err
		}

		n.Members = append(n.Members, Member{Key: key, KeySpan: r.span, Value: child})
	}

	return n, nil
}
