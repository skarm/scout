package harness

import (
	"strconv"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// A nonblocking flock guard can skip a subshell body. Opening a dedicated
// append-only lock descriptor leaves the shell's standard streams intact.
func hookAppendLockSubshell(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("flock") || len(cmd.Redirects) != 1 || len(cmd.Subshell.Statements) < 2 {
		return false
	}

	redirect := cmd.Redirects[0]
	fd, err := strconv.Atoi(redirect.FD)

	if redirect.Op != ">>" || err != nil || fd < 3 || fd > 1023 || redirect.Target == nil ||
		!redirect.Target.Quoted || !hookFixedArgument(redirect.Target) || len(redirect.Target.Parts) != 1 {
		return false
	}

	part := redirect.Target.Parts[0]
	if part.Kind != "literal" && (part.Kind != "parameter" || !part.PlainParameter || !hookVariableName(part.Text)) {
		return false
	}

	probe, skip := cmd.Subshell.Statements[0], cmd.Subshell.Statements[1]
	if probe.Next != "||" || probe.Negated || probe.Background || len(probe.Commands) != 1 || !hookLockExit(skip, state) {
		return false
	}

	setup := probe.Commands[0]
	if len(setup.Words) != 3 || len(setup.Assignments) != 0 || len(setup.Redirects) != 0 {
		return false
	}

	name, _ := setup.Words[0].Literal()
	mode, _ := setup.Words[1].Literal()
	operand, _ := setup.Words[2].Literal()

	return name == "flock" && mode == "-n" && operand == redirect.FD
}

func hookLockExit(stmt *shellsyntax.Statement, state hookSourceState) bool {
	if stmt.Negated || stmt.Background || state.hasFunction("exit") {
		return false
	}

	cmd, simple := simpleShellCommand(&shellsyntax.File{Statements: []*shellsyntax.Statement{stmt}})
	if !simple || len(cmd.Words) != 2 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	code, _ := cmd.Words[1].Literal()

	return name == "exit" && code == "0"
}

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

		child.hookOutput = false
		w.statement(e, view, stage, chain, entrypoint, &child)

		if lastInCaller {
			child.hookOutput = state.hookOutput
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

	child := state.child()
	child.hookOutput = false
	w.commands(e, view, &shellsyntax.File{Statements: isolated}, child, chain, entrypoint)
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
	success.hookOutput = state.hookOutput && hookKeepsOutput(cmd.Redirects)

	w.command(e, view, body, chain, entrypoint, &success)
	success.hookOutput = state.hookOutput
	*state = state.join(success)

	return true
}

func hookGroupFileOutput(r *shellsyntax.Redirect) bool {
	// These redirects can fail or write a file but cannot assign a shell
	// variable or change command lookup. Substitutions are traced by command.
	return (r.Op == ">" || r.Op == ">>") && (r.FD == "" || r.FD == "1" || r.FD == "2") &&
		hookSingleBracketWord(r.Target)
}
