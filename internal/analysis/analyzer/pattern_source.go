package analyzer

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	patternSourceKinds = map[string]patternSourceKind{
		language.Markdown:   patternMarkdown,
		language.JavaScript: patternJavaScript,
		language.TypeScript: patternJavaScript,
	}
	patternDataLanguages = map[string]bool{language.JSON: true, language.YAML: true, language.TOML: true}
)

type patternSourceKind uint8

const (
	patternMarkdown patternSourceKind = 1 << iota
	patternJavaScript
	patternCode
)

type patternSource struct {
	text string
	kind patternSourceKind
}

func sourceForPattern(d document.File) patternSource {
	out := patternSource{text: d.Artifact().Content()}
	for _, hint := range d.Classification().Languages {
		out.kind |= patternSourceKinds[hint.Language]
		if language.Structured(hint.Language) && !patternDataLanguages[hint.Language] {
			out.kind |= patternCode
		}
	}

	return out
}

func (s patternSource) line(m Match) source.Span {
	at := source.Span{Start: strings.LastIndexByte(s.text[:m.Start], '\n') + 1, End: len(s.text)}
	if n := strings.IndexByte(s.text[m.End:], '\n'); n >= 0 {
		at.End = m.End + n
	}

	return at
}
