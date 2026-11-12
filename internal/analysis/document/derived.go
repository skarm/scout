package document

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// OriginGeneratedShell is the coverage origin for shell reconstructed from captured code.
const OriginGeneratedShell = "heredoc"

// GeneratedShellExecution binds a recovered write and body to a later command
// in the same captured object. All three spans use physical coordinates.
type GeneratedShellExecution struct {
	Write, Body, Use source.Span
}

func (f File) GeneratedShellExecutions() ([]GeneratedShellExecution, bool) {
	return append([]GeneratedShellExecution(nil), f.shellExecutions...), f.shellExecutionLimit
}

func (f File) WithGeneratedShellExecutions(executions []GeneratedShellExecution, limited bool) File {
	remaining := MaxRegions - len(f.shellExecutions)

	f.shellExecutionLimit = f.shellExecutionLimit || limited || len(executions) > remaining
	if len(executions) > 0 && remaining > 0 {
		f.shellExecutions = append(append([]GeneratedShellExecution(nil), f.shellExecutions...), executions[:min(remaining, len(executions))]...)
	}

	return f
}

// WithGeneratedShell adds source-mapped units before preparation is frozen.
func (f File) WithGeneratedShell(ctx context.Context, views []source.View, limited bool) File {
	if len(views) > 0 {
		f.units = append([]Unit(nil), f.units...)
	}

	projection := (*filePreparation)(&f)

	for _, view := range views {
		span, err := view.Original(source.Span{End: len(view.Text())})
		if err != nil || f.budget == nil {
			limited = true
			continue
		}

		projection.addUnit(ctx, language.Shell, OriginGeneratedShell, span, view)
	}

	if limited {
		projection.issue("generated_shell_incomplete", "A generated shell script could not be recovered within the supported syntax and preparation limits.")
	}

	return f
}

// DerivedInput is a bounded, non-executed configuration written by source syntax.
// Its evidence remains the enclosing source span, including after expansion.
type DerivedInput struct {
	Name, Text string
	Span       source.Span
}

type derivedConfig struct {
	Span source.Span
	File *File
}

// Freeze closes preparation ownership before concurrent checks receive units.
// Only this sequential stage can retain a parser registry or mutate its budget.
func Freeze(files []File) []File {
	out := append([]File(nil), files...)
	for i := range out {
		out[i].budget = nil
		out[i].registry = parse.Registry{}

		out[i].derived = append([]derivedConfig(nil), out[i].derived...)
		for j := range out[i].derived {
			if child := out[i].derived[j].File; child != nil {
				frozen := Freeze([]File{*child})
				out[i].derived[j].File = &frozen[0]
			}
		}
	}

	return out
}

func (f File) DerivedConfigs() ([]derivedConfig, bool) {
	return append([]derivedConfig(nil), f.derived...), f.derivedGap
}

// WithDerivedInputs belongs to the sequential preparation stage. Every derived
// input uses this run's selected registry and shared aggregate parser budget.
func (f File) WithDerivedInputs(ctx context.Context, inputs []DerivedInput, limited bool) File {
	projection := (*filePreparation)(&f)
	if f.derivedReady {
		return f
	}

	f.derivedReady = true

	f.derivedGap = limited
	if f.budget == nil {
		f.derivedGap = true

		projection.issue("derived_preparation_closed", "Derived preparation cannot run after the immutable preparation boundary.")

		return f
	}

	seen := make(map[DerivedInput]bool)

	for _, input := range inputs {
		if len(f.derived) >= MaxRegions {
			f.derivedGap = true
			break
		}

		if seen[input] {
			continue
		}

		seen[input] = true
		projection.prepareDerivedInput(ctx, input)
	}

	if f.derivedGap {
		projection.issue("derived_config_incomplete", "A generated configuration could not be fully prepared under the selected parsers and budgets.")
	}

	return f
}

func (f *filePreparation) prepareDerivedInput(ctx context.Context, input DerivedInput) {
	child := prepare(ctx, artifact.NewFile(input.Name, []byte(input.Text), false), f.budget, f.registry)
	for _, unit := range child.units {
		f.derivedGap = f.derivedGap || unit.Status != report.UnitParsedLimited
	}

	for _, d := range child.diagnostics {
		if !strings.HasSuffix(d.Code, "_semantics_limited") {
			f.derivedGap = true
			f.issue("derived_"+d.Code, "Derived configuration preparation is incomplete; evidence belongs to its enclosing source.")
		}
	}

	f.derived = append(f.derived, derivedConfig{Span: input.Span, File: &child})
}
