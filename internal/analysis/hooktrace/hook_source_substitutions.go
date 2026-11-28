package hooktrace

import (
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) traceSubstitutions(e *File, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) {
	for _, word := range cmd.NumericTest {
		w.traceWordSubstitutions(e, view, word, state, chain)
	}

	for _, word := range cmd.ExpansionWords {
		w.traceWordSubstitutions(e, view, word, state, chain)
	}

	for _, word := range cmd.Words {
		w.traceWordSubstitutions(e, view, word, state, chain)
	}

	for _, assignment := range cmd.Assignments {
		w.traceWordSubstitutions(e, view, assignment.Value, state, chain)
	}

	for _, redirect := range cmd.Redirects {
		w.traceWordSubstitutions(e, view, redirect.Target, state, chain)
		w.traceWordSubstitutions(e, view, redirect.Body, state, chain)
	}
}

func (w *hookSourceWalk) traceWordSubstitutions(e *File, view source.View, word *shellsyntax.Word, state hookSourceState, chain []report.SourceRef) {
	if word == nil {
		return
	}

	for tree := range word.SubstitutionsExcept(func(part shellsyntax.Part) bool {
		return !word.Writes && w.knownPluginDefault(part, state)
	}) {
		if hookCountPipeline(tree, state) {
			continue
		}

		// The projection retains only forms that run in an isolated shell.
		child := state.child()
		child.hookOutput = false
		w.commands(e, view, tree, child, chain, true)
	}
}
