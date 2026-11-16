package harness

import (
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// traceForkedStatement keeps normal pipeline stages and background jobs in
// isolated shell scopes. The final foreground stage may run in the caller
// under Bash lastpipe, so it contributes a second possible continuation.
func (w *hookSourceWalk) traceForkedStatement(e *entry, view source.View, stmt *shellsyntax.Statement, state *hookSourceState, chain []report.SourceRef, entrypoint bool) bool {
	background := stmt.Background || stmt.Next == "&"
	if !background && len(stmt.Commands) < 2 {
		return false
	}

	for i, cmd := range stmt.Commands {
		if !w.plugin.b.step() {
			*state = state.opaque()
			break
		}

		if !state.lookupUnknown && hookPipelineStage(cmd, *state) {
			w.traceSubstitutions(e, view, cmd, *state, chain)
			continue
		}

		stage := &shellsyntax.Statement{Span: cmd.Span, Commands: []*shellsyntax.Command{cmd}}
		child := state.child()

		lastInCaller := !background && i == len(stmt.Commands)-1
		if lastInCaller {
			child = state.clone()
		}

		w.statement(e, view, stage, chain, entrypoint, &child)

		if lastInCaller {
			*state = state.join(child)
		}
	}

	return true
}

func (w *hookSourceWalk) traceBackgroundList(e *entry, view source.View, stmts []*shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool) {
	isolated := make([]*shellsyntax.Statement, 0, len(stmts))
	for _, original := range stmts {
		stmt := *original
		stmt.Background = false

		if stmt.Next == "&" {
			stmt.Next = ""
		}

		isolated = append(isolated, &stmt)
	}

	w.commands(e, view, &shellsyntax.File{Statements: isolated}, state.child(), chain, entrypoint)
}

func (w *hookSourceWalk) traceRedirectedGroup(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef, entrypoint bool) bool {
	if (cmd.Group == nil && cmd.Case == nil && !cmd.ExclusiveBranches) || len(cmd.Redirects) == 0 ||
		len(cmd.Words) != 0 || len(cmd.Assignments) != 0 || len(cmd.Invalidates) != 0 {
		return false
	}

	for _, redirect := range cmd.Redirects {
		if !hookDiscardedOutput(redirect) && !hookStdinRedirect(redirect) &&
			(state.locals != nil || cmd.Case != nil || !hookGroupFileOutput(redirect)) {
			return false
		}
	}

	// The group runs only after its redirects succeed. Analyze the original
	// group and merge with the state in which the redirect failed.
	inner := *cmd
	inner.Redirects = nil
	body := &shellsyntax.Statement{Span: cmd.Span, Commands: []*shellsyntax.Command{&inner}}
	success := state.clone()

	w.command(e, view, body, chain, entrypoint, &success)
	*state = state.join(success)

	return true
}

func hookGroupFileOutput(r *shellsyntax.Redirect) bool {
	// These redirects can fail or write a file but cannot assign a shell
	// variable or change command lookup. Substitutions are traced by command.
	return (r.Op == ">" || r.Op == ">>") && (r.FD == "" || r.FD == "1" || r.FD == "2") &&
		hookSingleBracketWord(r.Target)
}
