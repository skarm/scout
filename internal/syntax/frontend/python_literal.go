package frontend

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

//nolint:gochecknoglobals // Read-only IR schema and Python grammar tables are shared by scans.
var pythonLiteralPrefixes = map[string]pythonLiteralPrefix{
	"":  {},
	"u": {},
	"r": {raw: true},
	"b": {bytes: true},
	"br": {
		raw:   true,
		bytes: true,
	},
	"rb": {
		raw:   true,
		bytes: true,
	},
}

//nolint:gochecknoglobals // Read-only IR schema and Python grammar tables are shared by scans.
var pythonEscapedBytes = map[byte]byte{
	'\\': '\\',
	'\'': '\'',
	'"':  '"',
	'a':  '\a',
	'b':  '\b',
	'f':  '\f',
	'n':  '\n',
	'r':  '\r',
	't':  '\t',
	'v':  '\v',
}

type pythonLiteralPrefix struct{ raw, bytes bool }

// pythonLiteral interprets a bounded subset of values of an already parsed
// Tree-sitter string node. It is NOT a Python lexer/parser. Unknown literal
// semantics become an explicit projection gap; they are never guessed.
func pythonLiteral(s string) (string, bool, bool) {
	i := strings.IndexAny(s, "\"'")
	if i < 0 || i > 2 {
		return "", false, false
	}

	prefix, ok := pythonLiteralPrefixes[strings.ToLower(s[:i])]
	if !ok {
		return "", false, false
	}

	raw, bytesValue := prefix.raw, prefix.bytes

	quote := s[i : i+1]

	n := 1
	if strings.HasPrefix(s[i:], strings.Repeat(quote, 3)) {
		n = 3
	}

	delim := strings.Repeat(quote, n)
	if len(s) < i+2*n || !strings.HasSuffix(s, delim) {
		return "", false, false
	}

	body := s[i+n : len(s)-n]

	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	if bytesValue && !asciiLiteral(body) {
		return "", false, false
	}

	if raw {
		return body, bytesValue, true
	}

	return decodePythonLiteral(body, bytesValue)
}

func decodePythonLiteral(body string, bytesValue bool) (string, bool, bool) {
	var out strings.Builder
	out.Grow(len(body))

	for j := 0; j < len(body); j++ {
		if body[j] != '\\' {
			out.WriteByte(body[j])
			continue
		}

		j++
		if j >= len(body) {
			return "", false, false
		}

		var ok bool

		j, ok = writePythonEscape(&out, body, j, bytesValue)
		if !ok {
			return "", false, false
		}
	}

	return out.String(), bytesValue, true
}

func writePythonHex(out *strings.Builder, body string, at int, bytesValue bool) (int, bool) {
	c := body[at]
	if bytesValue && c != 'x' {
		out.WriteByte('\\')
		out.WriteByte(c)

		return at, true
	}

	width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]

	if at+width >= len(body) {
		return at, false
	}

	value, err := strconv.ParseUint(body[at+1:at+1+width], 16, 32)
	if err != nil {
		return at, false
	}

	if bytesValue {
		if value > 255 {
			return at, false
		}

		out.WriteByte(byte(value))
	} else {
		if value > utf8.MaxRune || !utf8.ValidRune(rune(value)) {
			return at, false
		}

		out.WriteRune(rune(value))
	}

	return at + width, true
}

func writePythonOtherEscape(out *strings.Builder, body string, at int, bytesValue bool) (int, bool) {
	c := body[at]
	if c < '0' || c > '7' {
		// Python retains unknown escapes.
		out.WriteByte('\\')
		out.WriteByte(c)

		return at, true
	}

	value := uint32(c - '0')

	for k := 0; k < 2 && at+1 < len(body) && body[at+1] >= '0' && body[at+1] <= '7'; k++ {
		at++
		value = value*8 + uint32(body[at]-'0')
	}

	if bytesValue {
		if value > 255 {
			return at, false
		}

		out.WriteByte(byte(value))
	} else {
		out.WriteRune(rune(value))
	}

	return at, true
}

func asciiLiteral(body string) bool {
	for _, r := range body {
		if r > 127 {
			return false
		}
	}

	return true
}

func writePythonEscape(out *strings.Builder, body string, at int, bytesValue bool) (int, bool) {
	c := body[at]
	if escaped, ok := pythonEscapedBytes[c]; ok {
		out.WriteByte(escaped)
		return at, true
	}

	switch c {
	case '\n':
		return at, true
	case 'x', 'u', 'U':
		return writePythonHex(out, body, at, bytesValue)
	case 'N':
		if !bytesValue {
			return at, false
		}

		out.WriteString(`\N`)

		return at, true
	default:
		return writePythonOtherEscape(out, body, at, bytesValue)
	}
}
