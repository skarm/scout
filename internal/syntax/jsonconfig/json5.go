package jsonconfig

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

var json5Number = regexp.MustCompile(`^[+-]?(?:Infinity|NaN|0[xX][0-9a-fA-F]+|(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$`)

type json5Reader struct {
	ctx   context.Context
	text  string
	at    int
	nodes int
}

// ParseJSON5 retains original byte spans and applies the same structural
// limits and decoded-key and Unicode policies as strict JSON.
func ParseJSON5(ctx context.Context, text string) (*Node, error) {
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

	r := json5Reader{ctx: ctx, text: text}

	n, err := r.value(0)
	if err != nil {
		return nil, err
	}

	if err := r.space(); err != nil {
		return nil, err
	}

	if r.at != len(text) {
		return nil, &Error{Code: codeTrailingData}
	}

	return n, nil
}

func (r *json5Reader) charge() error {
	r.nodes++
	if r.nodes > MaxNodes {
		return &Error{Code: codeNodeLimit}
	}

	return nil
}

func (r *json5Reader) space() error {
	for r.at < len(r.text) {
		remaining := r.text[r.at:]
		switch {
		case strings.HasPrefix(remaining, "//"):
			end := strings.IndexFunc(remaining[2:], json5Line)
			if end < 0 {
				r.at = len(r.text)
			} else {
				r.at += 2 + end
			}
		case strings.HasPrefix(remaining, "/*"):
			end := strings.Index(remaining[2:], "*/")
			if end < 0 {
				return &Error{Code: valueSyntaxError}
			}

			r.at += end + 4
		default:
			c, size := utf8.DecodeRuneInString(remaining)
			if !json5Space(c) {
				return r.ctx.Err()
			}

			r.at += size
		}
	}

	return r.ctx.Err()
}

func json5Space(c rune) bool {
	return json5Line(c) || c == '\t' || c == '\v' || c == '\f' || c == '\ufeff' || unicode.Is(unicode.Zs, c)
}

func json5Line(c rune) bool { return c == '\n' || c == '\r' || c == '\u2028' || c == '\u2029' }

func (r *json5Reader) next() byte {
	if r.at == len(r.text) {
		return 0
	}

	return r.text[r.at]
}

func (r *json5Reader) take(c byte) bool {
	if r.next() != c {
		return false
	}

	r.at++

	return true
}

func (r *json5Reader) value(depth int) (*Node, error) {
	if depth > MaxDepth {
		return nil, &Error{Code: codeDepthLimit}
	}

	if err := r.space(); err != nil {
		return nil, err
	}

	if err := r.charge(); err != nil {
		return nil, err
	}

	n := &Node{Span: source.Span{Start: r.at}}
	switch r.next() {
	case '{', '[':
		if err := r.composite(n, depth); err != nil {
			return nil, err
		}
	case '\'', '"':
		value, err := r.quoted()
		if err != nil {
			return nil, err
		}

		n.Kind, n.String, n.json5 = KindString, value, true
	default:
		if !r.scalar(n) {
			return nil, &Error{Code: valueSyntaxError}
		}
	}

	n.Span.End = r.at

	return n, nil
}

func (r *json5Reader) scalar(n *Node) bool {
	start := r.at
	for r.at < len(r.text) {
		c, size := utf8.DecodeRuneInString(r.text[r.at:])
		if json5Space(c) || strings.ContainsRune(",]}:/", c) {
			break
		}

		r.at += size
	}

	token := r.text[start:r.at]
	switch token {
	case "true", "false":
		n.Kind, n.Bool = KindBool, token == "true"
	case "null":
		n.Kind = KindNull
	default:
		if !json5Number.MatchString(token) {
			return false
		}

		n.Kind, n.String = KindNumber, token
	}

	return true
}

func (r *json5Reader) composite(n *Node, depth int) error {
	closing := byte(']')
	n.Kind = KindArray

	var keys map[string]struct{}

	if r.next() == '{' {
		closing, n.Kind = '}', KindObject
		keys = make(map[string]struct{})
	}

	r.at++

	for {
		if err := r.space(); err != nil {
			return err
		}

		if r.take(closing) {
			return nil
		}

		if n.Kind == KindObject {
			member, err := r.member(keys, depth)
			if err != nil {
				return err
			}

			n.Members = append(n.Members, member)
		} else {
			child, err := r.value(depth + 1)
			if err != nil {
				return err
			}

			n.Elements = append(n.Elements, child)
		}

		if err := r.space(); err != nil {
			return err
		}

		if r.take(closing) {
			return nil
		}

		if !r.take(',') {
			return &Error{Code: valueSyntaxError}
		}
	}
}

func (r *json5Reader) member(keys map[string]struct{}, depth int) (Member, error) {
	if err := r.charge(); err != nil {
		return Member{}, err
	}

	start := r.at

	key, err := r.key()
	if err != nil {
		return Member{}, err
	}

	if _, duplicate := keys[key]; duplicate {
		return Member{}, &Error{Code: CodeDuplicateKey}
	}

	keys[key] = struct{}{}
	span := source.Span{Start: start, End: r.at}

	if err := r.space(); err != nil {
		return Member{}, err
	}

	if !r.take(':') {
		return Member{}, &Error{Code: valueSyntaxError}
	}

	child, err := r.value(depth + 1)

	return Member{Key: key, KeySpan: span, Value: child}, err
}

func (r *json5Reader) key() (string, error) {
	if c := r.next(); c == '\'' || c == '"' {
		return r.quoted()
	}

	var name strings.Builder

	for r.at < len(r.text) {
		ch, size := utf8.DecodeRuneInString(r.text[r.at:])

		escaped := ch == '\\'
		if escaped {
			ch, size = json5Hex(r.text[r.at:], 'u', 4)
			if size == 0 {
				return "", &Error{Code: valueSyntaxError}
			}
		}

		if !json5Identifier(ch, name.Len() == 0) {
			if escaped {
				return "", &Error{Code: valueSyntaxError}
			}

			break
		}

		name.WriteRune(ch)

		r.at += size
	}

	if name.Len() == 0 {
		return "", &Error{Code: valueSyntaxError}
	}

	return name.String(), nil
}

func json5Identifier(c rune, first bool) bool {
	if c == '$' || c == '_' || unicode.IsLetter(c) || unicode.Is(unicode.Nl, c) {
		return true
	}

	return !first && (c == '\u200c' || c == '\u200d' || unicode.In(c, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc))
}

func (r *json5Reader) quoted() (string, error) {
	quote := r.next()
	r.at++

	var value strings.Builder

	for r.at < len(r.text) {
		c := r.next()
		switch c {
		case quote:
			r.at++
			return value.String(), nil
		case '\\':
			end, decoded, ok := decodeJSON5Escape(r.text, r.at)
			if !ok {
				return "", &Error{Code: valueSyntaxError}
			}

			value.WriteString(decoded)

			r.at = end
		case '\r', '\n':
			return "", &Error{Code: valueSyntaxError}
		default:
			value.WriteByte(c)

			r.at++
		}
	}

	return "", &Error{Code: valueSyntaxError}
}

func json5Hex(text string, prefix byte, digits int) (rune, int) {
	size := digits + 2
	if len(text) < size || text[0] != '\\' || text[1] != prefix {
		return 0, 0
	}

	for _, c := range text[2:size] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return 0, 0
		}
	}

	value, err := strconv.ParseUint(text[2:size], 16, 16)
	if err != nil {
		return 0, 0
	}

	return rune(value), size // bounded to four hexadecimal digits
}

func decodeJSON5Escape(text string, at int) (int, string, bool) {
	if at+1 >= len(text) {
		return 0, "", false
	}

	c, size := utf8.DecodeRuneInString(text[at+1:])
	end := at + 1 + size

	switch c {
	case 'u', 'x':
		return json5ScalarEscape(text, at, byte(c))
	case '0':
		return end, "\x00", end == len(text) || text[end] < '0' || text[end] > '9'
	case '\r':
		if end < len(text) && text[end] == '\n' {
			end++
		}

		return end, "", true
	case '\n', '\u2028', '\u2029':
		return end, "", true
	case 'b':
		return end, "\b", true
	case 'f':
		return end, "\f", true
	case 'n':
		return end, "\n", true
	case 'r':
		return end, "\r", true
	case 't':
		return end, "\t", true
	case 'v':
		return end, "\v", true
	default:
		return end, string(c), c < '0' || c > '9'
	}
}

func json5ScalarEscape(text string, at int, prefix byte) (int, string, bool) {
	digits := 4
	if prefix == 'x' {
		digits = 2
	}

	ch, size := json5Hex(text[at:], prefix, digits)
	if size == 0 {
		return 0, "", false
	}

	end := at + size
	if utf16.IsSurrogate(ch) {
		low, length := json5Hex(text[end:], 'u', 4)

		ch = utf16.DecodeRune(ch, low)
		if ch == utf8.RuneError {
			return 0, "", false
		}

		end += length
	}

	return end, string(ch), true
}
