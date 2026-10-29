package document

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
)

// A retry keeps the first accepted projection of each grammar. A declaration
// can be complete on the first line while execution needs a later continuation.
type shellCandidateRetry struct {
	execution, declaration *shellProjection
	last                   Unit
	span                   source.Span
	view                   source.View
	limited                bool
}

type shellProjection struct {
	unit Unit
	tree parse.ShellTree
}

// ShellCandidates exposes only auxiliary prose projections. Their execution
// and declaration trees can have different accepted extents; each retains the
// view used by its parser. They do not declare a structured source language or
// create ordinary unit coverage and validation obligations.
func (f File) ShellCandidates() ([]Unit, bool) {
	return append([]Unit(nil), f.shellUnits...), f.shellGap
}

// WithShellCandidates treats each span as an initial candidate line. Bounded grammar retries and
// both parser projections spend this run's original registry/byte/operation
// budgets. A previously parsed document never opens a second preparation phase.
func (f File) WithShellCandidates(ctx context.Context, spans []source.Span, limited bool) File {
	projection := (*filePreparation)(&f)
	if f.shellReady {
		return f
	}

	f.shellReady, f.shellGap = true, limited
	if f.budget == nil {
		f.shellGap = true

		return f
	}

	f.shellUnits = append([]Unit(nil), f.shellUnits...)
	for _, span := range spans {
		if len(f.units)+len(f.shellUnits) >= MaxRegions {
			f.shellGap = true
			break
		}

		projection.shellCandidate(ctx, span)

		if analysisbudget.Exhausted(ctx) || ctx.Err() != nil {
			f.shellGap = true
			break
		}
	}

	return f
}

func (f *filePreparation) shellCandidate(ctx context.Context, span source.Span) {
	text := f.file.Content()

	view, err := source.NewView(text, []source.Span{span})
	if err != nil {
		f.shellGap = true
		return
	}

	retry := shellCandidateRetry{span: span, view: view}

	for range 8 {
		if !analysisbudget.Consume(ctx, 1) {
			f.shellGap = true
			break
		}

		retry.observe(f.parseUnit(ctx, language.Shell, "shell-prose", retry.span, retry.view), text)

		if retry.complete() || !retry.advance(text) {
			break
		}
	}

	f.shellGap = f.shellGap || retry.limited
	f.publishShellProjection(retry.execution, retry.declaration, retry.last)
}

func (f *filePreparation) publishShellProjection(execution, declaration *shellProjection, last Unit) {
	if last.Language == "" {
		return
	}

	unit := last
	tree := parse.ShellTree{}

	if execution != nil {
		unit = execution.unit
		tree.Tree = execution.tree.Tree
	}

	if declaration != nil {
		if execution == nil {
			unit = declaration.unit
		}

		parsed := declaration.tree
		tree.Declarations, tree.DeclarationError = parsed.Declarations, parsed.DeclarationError
		view := declaration.unit.View
		tree.DeclarationView = &view
	}

	unit.Tree = tree

	// A heuristic candidate can simply be prose outside either shell grammar.
	// Only an unfinished preparation task, not a rejected grammar, is a gap.
	switch last.Status {
	case "budget_exceeded", "not_run", "unavailable", "failed", "unsupported":
		f.shellGap = true
	}

	f.shellUnits = append(f.shellUnits, unit)
}

func (r *shellCandidateRetry) observe(unit Unit, text string) {
	r.last = unit
	tree, ok := unit.Tree.(parse.ShellTree)
	r.limited = r.limited || parse.FailureCategory(tree.DeclarationError) == "parser_limit"

	continued := r.span.End < len(text) && strings.HasSuffix(strings.TrimRight(r.view.Text(), "\r\n"), `\`)
	if !ok || continued {
		return
	}

	if tree.ExecutionError == nil && r.execution == nil {
		accepted := shellProjection{unit: unit, tree: tree}
		r.execution = &accepted
	}

	if tree.DeclarationError == nil && r.declaration == nil {
		accepted := shellProjection{unit: unit, tree: tree}
		r.declaration = &accepted
	}
}

func (r *shellCandidateRetry) complete() bool {
	switch r.last.Status {
	case "budget_exceeded", "not_run", "unavailable", "failed", "unsupported":
		return true
	}

	return r.limited || r.execution != nil && r.declaration != nil
}

func (r *shellCandidateRetry) advance(text string) bool {
	if r.span.End == len(text) || r.span.End-r.span.Start > 8192 {
		return false
	}

	r.span.End = nextLine(text, r.span.End).next
	r.view, _ = source.NewView(text, []source.Span{r.span}) // Valid initial span extended to a physical line boundary.

	return true
}
