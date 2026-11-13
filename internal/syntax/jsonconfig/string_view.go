package jsonconfig

import (
	"encoding/json"
	"strings"

	"github.com/skarm/scout/internal/syntax/source"
)

// StringView decodes a parsed string and maps each escape to the original token.
func StringView(parent source.View, node *Node, maxEscapes int) (source.View, bool) {
	value, ok := node.Text()
	if !ok || node.Span.End-node.Span.Start < 2 {
		return source.View{}, false
	}

	raw, err := parent.Select([]source.Span{{Start: node.Span.Start + 1, End: node.Span.End - 1}})
	if err != nil {
		return source.View{}, false
	}

	text := raw.Text()
	if text == value {
		return raw, true
	}

	token := parent.Text()[node.Span.Start:node.Span.End]

	var changes []source.Replacement

	for at := 0; at < len(text); {
		next := strings.IndexByte(text[at:], '\\')
		if next < 0 {
			break
		}

		at += next

		end, decoded, ok := decodeEscape(token, at+1)
		if !ok || len(changes) >= maxEscapes {
			return source.View{}, false
		}

		changes = append(changes, source.Replacement{Span: source.Span{Start: at, End: end - 1}, Text: decoded})
		at = end - 1
	}

	view, err := raw.Replace(changes)

	return view, err == nil && view.Text() == value
}

func decodeEscape(text string, at int) (int, string, bool) {
	end := at + 2
	if end > len(text)-1 {
		return 0, "", false
	}

	if text[at+1] == 'u' {
		var ok bool

		end, ok = unicodeScalarEnd(text, at)
		if !ok {
			return 0, "", false
		}
	}

	var decoded string

	err := json.Unmarshal([]byte(`"`+text[at:end]+`"`), &decoded)

	return end, decoded, err == nil
}
