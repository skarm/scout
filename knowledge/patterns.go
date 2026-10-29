package knowledge

import "encoding/json"

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var additionalPatterns = func() map[string][]Pattern {
	b, e := content.ReadFile("data/patterns.json")
	if e != nil {
		panic("missing embedded patterns")
	}

	var p map[string][]Pattern
	if json.Unmarshal(b, &p) != nil {
		panic("invalid embedded patterns")
	}

	return p
}()

// Pattern records a supplemental expression, its source and its adaptation
// notes.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type Pattern struct {
	// Expression contains the supplemental pattern expression associated with a
	// rule.
	Expression string `json:"expression"`
	// Source identifies the reference from which the expression was adapted.
	Source string `json:"source"`
	// Adaptation states how the expression was adapted for Scout.
	Adaptation string `json:"adaptation"`
}

// Patterns returns a copy of the supplemental patterns for id, or nil if none
// are registered.
func Patterns(id string) []Pattern { return append([]Pattern(nil), additionalPatterns[id]...) }

// PatternCatalog returns a detached copy of all supplemental patterns grouped
// by rule identity.
func PatternCatalog() map[string][]Pattern {
	out := map[string][]Pattern{}
	for id := range additionalPatterns {
		out[id] = Patterns(id)
	}

	return out
}
