// Package jsonconfig builds a bounded, source-located JSON tree using the Go
// standard decoder. It never loads files, resolves references or executes hooks.
package jsonconfig

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

const (
	MaxBytes = 256 << 10
	MaxDepth = 32
	MaxNodes = 8192
)

const (
	valueSyntaxError = "syntax_error"
)

// Node and Member are private to one preparation pass. Only trusted read-only
// checks receive them. Values are not copied to public reports.
type Node struct {
	Kind     string
	Span     source.Span
	String   string
	Bool     bool
	Members  []Member
	Elements []*Node
}

type Member struct {
	Key     string
	KeySpan source.Span
	Value   *Node
}

// Error never contains input text. No partial configuration tree is returned:
// an ambiguous key or malformed document cannot choose which policy to inspect.
type Error struct{ Code string }

type reader struct {
	ctx      context.Context
	text     string
	decoder  *json.Decoder
	nodes    int
	maxNodes int
}

func Parse(ctx context.Context, text string) (*Node, error) {
	return ParseWithNodeLimit(ctx, text, MaxNodes)
}

// ParseWithNodeLimit retains the byte, depth and strict JSON policies while
// allowing trusted callers to choose a bounded node inventory for their schema.
func ParseWithNodeLimit(ctx context.Context, text string, maxNodes int) (*Node, error) {
	if ctx == nil {
		return nil, &Error{Code: "nil_context"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if maxNodes < 1 || maxNodes > MaxBytes {
		return nil, &Error{Code: "invalid_node_limit"}
	}

	if len(text) > MaxBytes {
		return nil, &Error{Code: "byte_limit"}
	}

	if !utf8.ValidString(text) {
		return nil, &Error{Code: "invalid_unicode"}
	}

	r := reader{ctx: ctx, text: text, decoder: json.NewDecoder(strings.NewReader(text)), maxNodes: maxNodes}
	r.decoder.UseNumber()

	n, err := r.value(0)
	if err != nil {
		return nil, err
	}

	if _, err = r.decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, &Error{Code: "trailing_data"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return n, nil
}

// ValidStringUnicode checks scalar encoding in one decoder-validated JSON string
// token. Tree and streaming consumers share rejection of malformed UTF-8 and
// lone UTF-16 surrogate escapes that encoding/json would replace with U+FFFD.
func ValidStringUnicode(raw string) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || !utf8.ValidString(raw) {
		return false
	}

	for i := 1; i < len(raw)-1; {
		if raw[i] != '\\' {
			i++
			continue
		}

		if i+1 >= len(raw)-1 {
			return false
		}

		if raw[i+1] != 'u' {
			i += 2
			continue
		}

		next, ok := unicodeScalarEnd(raw, i)
		if !ok {
			return false
		}

		i = next
	}

	return true
}

func (n *Node) Get(key string) *Node {
	if n == nil {
		return nil
	}

	for _, m := range n.Members {
		if m.Key == key {
			return m.Value
		}
	}

	return nil
}

func (n *Node) GetOrEmpty(key string) *Node {
	if v := n.Get(key); v != nil {
		return v
	}

	return &Node{}
}

func (n *Node) Text() (string, bool) {
	if n == nil || n.Kind != KindString {
		return "", false
	}

	return n.String, true
}

func (e *Error) Error() string { return "configuration JSON: " + e.Code }

func (r *reader) token() (json.Token, source.Span, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, source.Span{}, err
	}

	start := int(r.decoder.InputOffset())
	// InputOffset precedes separators/whitespace consumed by Token. These are
	// not part of a string value's evidence. Token still validates the grammar.
	for start < len(r.text) && strings.ContainsRune(" \t\r\n,:", rune(r.text[start])) {
		start++
	}

	t, err := r.decoder.Token()
	if err != nil {
		return nil, source.Span{}, &Error{Code: valueSyntaxError}
	}

	end := int(r.decoder.InputOffset())

	span := source.Span{Start: start, End: end}
	if start >= end || end > len(r.text) {
		return nil, source.Span{}, &Error{Code: "invalid_span"}
	}

	if _, ok := t.(string); ok && !ValidStringUnicode(r.text[start:end]) {
		return nil, span, &Error{Code: "invalid_unicode"}
	}

	return t, span, nil
}

func (r *reader) charge() error {
	r.nodes++
	if r.nodes > r.maxNodes {
		return &Error{Code: "node_limit"}
	}

	return nil
}

func (r *reader) value(depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, &Error{Code: "depth_limit"}
	}

	if err := r.charge(); err != nil {
		return nil, err
	}

	t, span, err := r.token()
	if err != nil {
		return nil, err
	}

	n := &Node{Span: span}

	switch v := t.(type) {
	case json.Delim:
		return r.composite(n, v, depth)
	case string:
		n.Kind, n.String = KindString, v
	case bool:
		n.Kind, n.Bool = KindBool, v
	case nil:
		n.Kind = KindNull
	// token uses Decoder.UseNumber; these cases exhaust JSON scalar tokens.
	case json.Number:
		n.Kind, n.String = KindNumber, string(v)
	}

	return n, nil
}

func (r *reader) object(n *Node, depth int) (*Node, error) {
	n.Kind = KindObject
	keys := make(map[string]bool)

	for r.decoder.More() {
		if err := r.charge(); err != nil {
			return nil, err
		}

		key, at, err := r.token()
		if err != nil {
			return nil, err
		}

		name, ok := key.(string)
		if !ok {
			return nil, &Error{Code: valueSyntaxError}
		}
		// Compare decoded keys, including their escaped spellings.
		if keys[name] {
			return nil, &Error{Code: "duplicate_key"}
		}

		keys[name] = true

		child, err := r.value(depth + 1)
		if err != nil {
			return nil, err
		}

		n.Members = append(n.Members, Member{Key: name, KeySpan: at, Value: child})
	}

	closing, at, err := r.token()
	if err != nil {
		return nil, err
	}

	if closing != json.Delim('}') {
		return nil, &Error{Code: valueSyntaxError}
	}

	n.Span.End = at.End

	return n, nil
}

func (r *reader) composite(n *Node, v json.Delim, depth int) (*Node, error) {
	switch v {
	case '{':
		return r.object(n, depth)
	case '[':
		n.Kind = KindArray

		for r.decoder.More() {
			child, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}

			n.Elements = append(n.Elements, child)
		}

		closing, at, err := r.token()
		if err != nil {
			return nil, err
		}

		if closing != json.Delim(']') {
			return nil, &Error{Code: valueSyntaxError}
		}

		n.Span.End = at.End
	default:
		return nil, &Error{Code: valueSyntaxError}
	}

	return n, nil
}

// A JSON Unicode escape is one non-surrogate code unit or one surrogate pair.
func unicodeScalarEnd(raw string, at int) (int, bool) {
	x, ok := escapedCodeUnit(raw, at)
	if !ok {
		return 0, false
	}

	at += 6
	if x >= 0xd800 && x <= 0xdbff {
		y, ok := escapedCodeUnit(raw, at)
		return at + 6, ok && y >= 0xdc00 && y <= 0xdfff
	}

	return at, x < 0xdc00 || x > 0xdfff
}

func escapedCodeUnit(raw string, at int) (uint64, bool) {
	if at+6 > len(raw)-1 || raw[at:at+2] != "\\u" {
		return 0, false
	}

	value, err := strconv.ParseUint(raw[at+2:at+6], 16, 16)

	return value, err == nil
}
