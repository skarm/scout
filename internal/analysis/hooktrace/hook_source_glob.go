package hooktrace

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) applyLoop(e *File, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	switch {
	case cmd.ForFileGlob != nil:
		return w.applyFileGlob(e, view, cmd, state, chain)
	case cmd.ForArguments != "":
		return w.applyArgumentLoop(e, view, cmd, state, chain)
	default:
		return w.applyWhile(e, view, cmd, state, chain)
	}
}

func (w *hookSourceWalk) applyFileGlob(e *File, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	glob := cmd.ForFileGlob

	root := pluginRootParameters[w.scope.Host]
	if !rootParameter(w.scope.Host, glob.Root, true) || state.rootUnknown || state.lookupUnknown ||
		!hookLocalVariable(glob.Name, root) || len(cmd.Redirects) != 0 || len(cmd.Alternatives) != 2 {
		return false
	}

	launch := w.globFileLaunch(cmd.Alternatives[0], glob.Name, *state)
	if launch == nil {
		return false
	}

	for rest := range w.scope.Descendants(glob.Directory) {
		if !w.trace.work.Spend(1) {
			w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "The shell file glob exceeded the source inspection budget.")
			break
		}

		// Only direct children are selected by the glob.
		if rest == "" || strings.ContainsRune(rest, '/') {
			continue
		}

		child := state.child()
		child.bindValue(glob.Name, pluginRootMarker+glob.Directory+"/"+rest, true)
		w.resolveCommand(e, view, launch, language.ExecutableBash, child, chain)
	}

	state.bindValue(glob.Name, "", false)

	return true
}

func (w *hookSourceWalk) globFileLaunch(body *shellsyntax.File, name string, state hookSourceState) *shellsyntax.Command {
	if len(body.Statements) != 3 {
		return nil
	}

	check, launch, fallback := body.Statements[0], body.Statements[1], body.Statements[2]

	if len(check.Commands) != 1 || len(check.Commands[0].Words) != 4 || !hookReadOnlyBracket(check.Commands[0], state) ||
		check.Negated || check.Background || check.Next != shellsyntax.AndThen || launch.Next != shellsyntax.OrElse ||
		!hookKnownStatus(fallback, state, "true") || !singleGlobLaunch(launch, state) {
		return nil
	}

	test := check.Commands[0]
	operator, _ := test.Words[1].Literal()

	cmd := launch.Commands[0]
	if operator != "-f" || !quotedGlobVariable(test.Words[2], name) || !quotedGlobVariable(cmd.Words[1], name) {
		return nil
	}

	return cmd
}

func singleGlobLaunch(stmt *shellsyntax.Statement, state hookSourceState) bool {
	if stmt.Negated || stmt.Background || len(stmt.Commands) != 1 || state.hasFunction(language.ExecutableBash) {
		return false
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) != 2 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	head, _ := cmd.Words[0].Literal()

	return head == language.ExecutableBash
}

func quotedGlobVariable(word *shellsyntax.Word, name string) bool {
	if word.Expands || word.Writes || len(word.Parts) != 1 {
		return false
	}

	part := word.Parts[0]

	return part.Quoted && part.Kind == shellsyntax.PartParameter && part.Text == name
}
