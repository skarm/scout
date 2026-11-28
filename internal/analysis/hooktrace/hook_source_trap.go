package hooktrace

import (
	"slices"
	"strconv"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

const (
	maxHookTrapTextBytes = 512
)

type hookTrapCommands uint8

const (
	hookTrapExit hookTrapCommands = 1 << iota
	hookTrapEcho
	hookTrapRemove
	hookTrapTrue
	hookTrapRemoveDirectory
)

func hookTrapCommand(name string) hookTrapCommands {
	switch name {
	case "exit":
		return hookTrapExit
	case "echo":
		return hookTrapEcho
	case "rm":
		return hookTrapRemove
	case "rmdir":
		return hookTrapRemoveDirectory
	case "true":
		return hookTrapTrue
	default:
		return 0
	}
}

func (w *hookSourceWalk) applyHookTrap(args []*shellsyntax.Word, state *hookSourceState) bool {
	if state.lookupUnknown {
		return false
	}

	if hookIgnoresPipe(args) {
		return true
	}

	if len(args) != 2 {
		return false
	}

	action, literal := args[0].Literal()

	signal, _ := args[1].Literal()
	if !literal || len(action) > maxHookTrapTextBytes || (signal != "ERR" && signal != "EXIT") || state.hasFunction("exit") {
		return false
	}

	if !w.trace.work.Spend(1) {
		return false
	}

	parsed, err := shellsyntax.ParseDeclarations(w.trace.work.Context, action)
	if err != nil || parsed.OmittedExecution || len(parsed.Statements) < 1 || len(parsed.Statements) > 2 {
		return false
	}

	if signal == "EXIT" && w.registerCleanupTrap(parsed, action, state) {
		return true
	}

	exit := hookTrapStatement(parsed.Statements[len(parsed.Statements)-1], "exit")
	if exit == nil || len(exit.Redirects) != 0 || len(exit.Words) != 2 {
		return false
	}

	status, literal := exit.Words[1].Literal()
	if _, err := strconv.ParseUint(status, 10, 8); !literal || err != nil {
		return false
	}

	commands := hookTrapExit

	if len(parsed.Statements) == 2 {
		if state.hasFunction("echo") || !hookTrapPrint(parsed.Statements[0]) {
			return false
		}

		commands |= hookTrapEcho
	}

	// An error trap can terminate a path earlier. The surviving path keeps
	// its bindings. A later function definition can change trap dispatch.
	state.trapCommands |= commands

	return true
}

func (w *hookSourceWalk) registerCleanupTrap(tree *shellsyntax.File, action string, state *hookSourceState) bool {
	if commands := hookCleanupTrap(tree, *state); commands != 0 {
		state.trapCommands |= commands
		return true
	}

	cmd, simple := SimpleShellCommand(tree)
	fn, known := state.singleFunction(action)

	if !simple || !known || len(cmd.Words) != 1 || hookTrapStatement(tree.Statements[0], action) == nil || !state.explicitBash {
		return false
	}

	body := cleanupFunctionBody(fn.body, pluginRootParameters[w.scope.Host])
	if body == nil {
		return false
	}

	commands := hookCleanupTrap(body, *state)
	if commands == 0 {
		return false
	}

	// The handler resolves its function name at exit. Protect both that
	// definition and each builtin or command used by its cleanup body.
	if state.trapFunctions == nil {
		state.trapFunctions = make(map[string]bool)
	}

	state.trapFunctions[action] = true
	state.trapCommands |= commands

	return true
}

func cleanupFunctionBody(tree *shellsyntax.File, root string) *shellsyntax.File {
	group := singleCleanupStatement(tree)
	if group == nil || group.Group == nil || !hookPlainCompound(group) {
		return nil
	}

	body := group.Group
	loop := singleCleanupStatement(body)

	if loop == nil || !loop.Loop {
		return body
	}

	if !hookPlainIteration(loop, root) || !hookCleanupLoopArray(loop) {
		return nil
	}

	return loop.Alternatives[0]
}

func singleCleanupStatement(tree *shellsyntax.File) *shellsyntax.Command {
	if tree == nil || len(tree.Statements) != 1 {
		return nil
	}

	stmt := tree.Statements[0]
	if stmt.Negated || stmt.Background || stmt.Next == shellsyntax.Background || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return nil
	}

	return stmt.Commands[0]
}

func hookCleanupLoopArray(loop *shellsyntax.Command) bool {
	if loop.ForArray != "" {
		return true
	}

	if len(loop.ForWords) != 1 || len(loop.ForWords[0].Parts) != 1 {
		return false
	}

	part := loop.ForWords[0].Parts[0]

	return part.Quoted && part.Kind == shellsyntax.PartParameterArrayAllDefaultEmpty
}

// A fixed cleanup command runs during process exit.
// Preserve the proof only while all of its command names remain unshadowed.
func hookCleanupTrap(tree *shellsyntax.File, state hookSourceState) hookTrapCommands {
	statements := tree.Statements
	if len(statements) == 0 || len(statements) > 2 {
		return 0
	}

	first := *statements[0]
	link := first.Next
	first.Next = ""

	if link != "&" && !hookAndOrLink(link) && len(statements) == 1 {
		if cmd := hookTrapStatement(&first, "rmdir"); cmd != nil && hookDirectoryOperation(cmd, state, "rmdir") {
			return hookTrapRemoveDirectory
		}
	}

	cmd := hookTrapStatement(&first, "rm")
	if state.hasFunction("rm") || cmd == nil || len(cmd.Redirects) > 1 || !hookCleanupOperands(cmd.Words) {
		return 0
	}

	if len(cmd.Redirects) == 1 && !hookCleanupRedirect(cmd.Redirects[0]) {
		return 0
	}

	if len(statements) == 1 && !hookAndOrLink(link) && link != "&" {
		return hookTrapRemove
	}

	if len(statements) == 2 && link == "||" && hookKnownStatus(statements[1], state, "true") {
		return hookTrapRemove | hookTrapTrue
	}

	return 0
}

func hookCleanupOperands(words []*shellsyntax.Word) bool {
	if len(words) < 3 || len(words) > 11 {
		return false
	}

	flag, _ := words[1].Literal()
	if flag != "-f" && flag != "-rf" && flag != "-fr" {
		return false
	}

	if len(words) == 3 {
		return hookTestOperand(words[2])
	}

	separator, _ := words[2].Literal()

	return separator == "--" && !slices.ContainsFunc(words[3:], func(operand *shellsyntax.Word) bool {
		return !hookCleanupOperand(operand)
	})
}

func hookCleanupOperand(word *shellsyntax.Word) bool {
	if hookTestOperand(word) {
		return true
	}

	if word.Writes || len(word.Parts) != 1 || !word.Parts[0].Quoted {
		return false
	}

	part := word.Parts[0]

	return part.Kind == shellsyntax.PartParameterArrayAll || part.Kind == shellsyntax.PartParameterArrayAllDefaultEmpty
}

func hookCleanupRedirect(r *shellsyntax.Redirect) bool {
	return r.Op == shellsyntax.RedirectOutput && r.FD == shellsyntax.StderrFD && hookDiscardedOutput(r)
}

func hookTrapStatement(stmt *shellsyntax.Statement, want string) *shellsyntax.Command {
	if len(stmt.Commands) != 1 || stmt.Negated || stmt.Background || hookAndOrLink(stmt.Next) {
		return nil
	}

	cmd := stmt.Commands[0]
	if cmd.FunctionName != "" || len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || cmd.Group != nil || cmd.Subshell != nil {
		return nil
	}

	name, _ := cmd.Words[0].Literal()
	if name != want {
		return nil
	}

	return cmd
}

func hookTrapPrint(stmt *shellsyntax.Statement) bool {
	cmd := hookTrapStatement(stmt, "echo")
	if cmd == nil || len(cmd.Redirects) != 1 {
		return false
	}

	r := cmd.Redirects[0]

	fd, _ := r.Target.Literal()
	if r.Op != shellsyntax.RedirectDuplicateOutput || (r.FD != "" && r.FD != shellsyntax.StdoutFD) || fd != "2" {
		return false
	}

	for _, arg := range cmd.Words[1:] {
		if _, literal := arg.Literal(); !literal {
			return false
		}
	}

	return true
}
