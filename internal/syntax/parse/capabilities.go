package parse

import (
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/report"
)

// Capabilities includes built-in and optional grammars, independently of Python
// selection. Both CLI and Go API use this single compiled capability inventory.
func Capabilities() []report.ParserCapability {
	var out []report.ParserCapability

	for _, b := range languageBackends() {
		d := b.Descriptor()
		out = append(out, report.ParserCapability{Format: d.Language, Name: d.ID, Version: d.Version, Available: true})
	}

	if !scriptsyntax.Available() {
		for _, lang := range []string{language.JavaScript, language.TypeScript} {
			d := (scriptBackend{language: lang}).Descriptor()
			out = append(out, report.ParserCapability{
				Format:  lang,
				Name:    d.ID,
				Version: d.Version,
				Reason:  "native script grammar is not linked",
			})
		}
	}

	for _, b := range frontend.Backends() {
		out = append(out, report.ParserCapability{
			Format:    b.Format,
			Name:      b.Name,
			Version:   b.Version,
			Available: b.Available,
			Reason:    b.Reason,
		})
	}

	return out
}
