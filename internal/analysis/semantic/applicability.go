package semantic

import (
	"slices"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/review"
)

const contentConfiguration = "configuration"

//nolint:gochecknoglobals // Read-only response and applicability grammar shared by review requests.
var languageContent = map[string]string{
	language.Unknown:            language.Unknown,
	language.Text:               language.Text,
	language.Markdown:           language.Markdown,
	language.JSON:               contentConfiguration,
	language.YAML:               contentConfiguration,
	language.TOML:               contentConfiguration,
	language.INI:                contentConfiguration,
	language.GoMod:              contentConfiguration,
	language.DependencyManifest: contentConfiguration,
}

var (
	//nolint:gochecknoglobals // Read-only response and applicability grammar shared by review requests.
	contentPriority = map[string]int{language.Unknown: 0, language.Text: 1, language.Markdown: 2, contentConfiguration: 3}
	//nolint:gochecknoglobals // Read-only response and applicability grammar shared by review requests.
	qualityContent = map[string][]string{
		"quality_vague_triggers":   {"markdown", "text", contentConfiguration},
		"quality_missing_warnings": {"code", "markdown"},
	}
)

// This is an applicability hint, not an execution or trust classification. Code
// candidates win conflicts so a .txt shebang cannot be used as a trigger manifest.
func contentKind(name, text string) string {
	kind := "unknown"

	for _, h := range language.Detect(name, text) {
		next, known := languageContent[h.Language]
		if !known {
			return "code"
		}

		if contentPriority[next] > contentPriority[kind] {
			kind = next
		}
	}

	return kind
}

// A quality claim needs at least one supporting excerpt of the rule's declared
// applicability. Related cross-file context may have other types. Unknown types
// do not silently establish eligibility. Security discovery remains unrestricted.
func qualityApplies(reason string, citations []review.Citation, excerpts []review.Excerpt) bool {
	if reason == "quality_language_policy" {
		return true
	}

	cited := map[string]bool{}
	for _, c := range citations {
		cited[c.ExcerptID] = true
	}

	for _, ex := range excerpts {
		if !cited[ex.ID] {
			continue
		}

		k := ex.ContentKind
		if k == "" {
			k = contentKind(ex.Path, ex.Text)
		}

		if slices.Contains(qualityContent[reason], k) {
			return true
		}
	}

	return false
}
