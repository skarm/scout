package document

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func (f *filePreparation) cordisFile() bool {
	name, host := f.hostConfigName, f.budget.host
	if artifact.DeepSeekCordisName(name) || artifact.DeepSeekSettingsName(name, host) {
		return true
	}

	// A separately captured bundle patch may have a custom name.
	return host == report.HostDeepSeekHarness && path.Dir(name) == "." && strings.Contains(f.file.Content(), "@deepseek-ai/")
}

func (f *filePreparation) deepSeekSkillFrontmatter() bool {
	name, host := f.hostConfigName, f.budget.host
	_, skill := artifact.DeepSeekSkillRoot(name, host)

	return skill || host == report.HostDeepSeekHarness && path.Dir(name) == "." && path.Ext(name) == ".md"
}

// WithCordisYAML prepares an already captured YAML file named by a DSH bundle.
// The manifest cannot supply bytes, choose a parser executable or expand roots.
func (f File) WithCordisYAML(ctx context.Context) File {
	if f.budget == nil || ctx.Err() != nil {
		return f
	}

	backend := parse.CordisYAML()

	for i, unit := range f.units {
		if unit.Origin != "file" || unit.Language != language.YAML {
			continue
		}

		if unit.ParserID == backend.Descriptor().ID {
			return f
		}

		f.units = slices.Delete(slices.Clone(f.units), i, i+1)
		f.diagnostics = slices.Clone(f.diagnostics)

		p := (*filePreparation)(&f)
		if unit.ParserID == "" && !slices.ContainsFunc(f.units, func(other Unit) bool {
			return other.Origin == "file" && other.ParserID == ""
		}) {
			p.diagnostics = slices.DeleteFunc(p.diagnostics, func(d report.Diagnostic) bool {
				return d.Code == "structural_analysis_unavailable"
			})
		}

		physical := Unit{Language: unit.Language, Origin: unit.Origin, Span: unit.Span, View: unit.View, Status: report.OutcomeUnsupported}
		p.publishUnit(ctx, p.parseWith(ctx, physical, backend))

		return f
	}

	return f
}
