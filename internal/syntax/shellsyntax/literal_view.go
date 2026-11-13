package shellsyntax

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/source"
)

// LiteralView projects a fixed shell word after quote removal. Parts must come
// from the execution parser, which retains the raw span of each literal.
func LiteralView(parent source.View, word *Word, maxParts int) (source.View, bool) {
	value, ok := word.Literal()
	if !ok || len(word.Parts) > maxParts {
		return source.View{}, false
	}

	text := parent.Text()

	spans := make([]source.Span, 0, len(word.Parts))
	for _, part := range word.Parts {
		if part.Text == "" {
			continue
		}

		at := part.Span
		if at.Start < 0 || at.End < at.Start || at.End > len(text) {
			return source.View{}, false
		}

		raw := text[at.Start:at.End]
		switch {
		case raw == part.Text:
		case raw == "'"+part.Text+"'":
			at.Start++
			at.End--
		case strings.HasPrefix(raw, `\`) && raw[1:] == part.Text:
			at.Start++
		default:
			return source.View{}, false
		}

		spans = append(spans, at)
	}

	view, err := parent.Select(spans)

	return view, err == nil && view.Text() == value
}
