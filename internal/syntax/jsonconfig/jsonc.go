package jsonconfig

import (
	"context"
	"strings"
	"unicode/utf8"
)

// ParseJSONC accepts comments and trailing commas while retaining byte offsets
// and the same duplicate-key, depth and node limits as strict JSON.
func ParseJSONC(ctx context.Context, text string) (*Node, error) {
	return parseCommentedJSON(ctx, text, true)
}

// ParseWithComments accepts comments and otherwise applies the strict JSON grammar.
func ParseWithComments(ctx context.Context, text string) (*Node, error) {
	return parseCommentedJSON(ctx, text, false)
}

func parseCommentedJSON(ctx context.Context, text string, trailingCommas bool) (*Node, error) {
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

	clean := []byte(text)
	if !maskJSONComments(text, clean) {
		return nil, &Error{Code: valueSyntaxError}
	}

	if trailingCommas {
		maskTrailingCommas(clean)
	}

	return Parse(ctx, string(clean))
}

func maskJSONComments(text string, clean []byte) bool {
	for i := 0; i < len(text); {
		switch {
		case text[i] == '"':
			i = afterQuoted(clean, i)
		case strings.HasPrefix(text[i:], "//"):
			end := i + 2
			for end < len(text) && text[end] != '\n' && text[end] != '\r' {
				end++
			}

			mask(clean[i:end])
			i = end
		case strings.HasPrefix(text[i:], "/*"):
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return false
			}

			end += i + 4
			mask(clean[i:end])
			i = end
		default:
			i++
		}
	}

	return true
}

func maskTrailingCommas(text []byte) {
	var previous byte

	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '"':
			i = afterQuoted(text, i)
			previous = c

			continue
		case jsonSpace(c):
		case c == ',' && previous != 0 && !strings.ContainsRune("{[,:", rune(previous)):
			next := i + 1
			for next < len(text) && jsonSpace(text[next]) {
				next++
			}

			if next < len(text) && (text[next] == '}' || text[next] == ']') {
				text[i] = ' '
			}

			previous = c
		default:
			previous = c
		}

		i++
	}
}

func afterQuoted(text []byte, start int) int {
	end := start + 1
	for end < len(text) {
		switch text[end] {
		case '"':
			return end + 1
		case '\\':
			end++
		}

		end++
	}

	return len(text)
}

func jsonSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func mask(text []byte) {
	for i, c := range text {
		if c != '\n' && c != '\r' {
			text[i] = ' '
		}
	}
}
