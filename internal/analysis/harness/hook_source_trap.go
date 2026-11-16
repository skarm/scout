package harness

import (
	"strconv"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

type hookTrapCommands uint8

const (
	hookTrapExit hookTrapCommands = 1 << iota
	hookTrapEcho
	hookTrapRemove
	hookTrapTrue
)

func hookTrapCommand(name string) hookTrapCommands {
	switch name {
	case "exit":
		return hookTrapExit
	case "echo":
		return hookTrapEcho
	case "rm":
		return hookTrapRemove
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
	if !literal || len(action) > 512 || (signal != "ERR" && signal != "EXIT") || state.hasFunction("exit") {
		return false
	}

	if !w.plugin.b.step() {
		return false
	}

	parsed, err := shellsyntax.ParseDeclarations(w.plugin.b.ctx, action)
	if err != nil || parsed.OmittedExecution || len(parsed.Statements) < 1 || len(parsed.Statements) > 2 {
		return false
	}

	if signal == "EXIT" {
		if commands := hookCleanupTrap(parsed, *state); commands != 0 {
			state.trapCommands |= commands
			return true
		}
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

// A fixed rm command with one scalar operand runs during process exit.
// Preserve the proof only while all of its command names remain unshadowed.
func hookCleanupTrap(tree *shellsyntax.File, state hookSourceState) hookTrapCommands {
	statements := tree.Statements
	first := *statements[0]
	link := first.Next
	first.Next = ""

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
	if len(words) != 3 && len(words) != 4 {
		return false
	}

	flag, _ := words[1].Literal()
	if flag != "-f" && flag != "-rf" && flag != "-fr" {
		return false
	}

	if len(words) == 4 {
		separator, _ := words[2].Literal()
		if separator != "--" {
			return false
		}
	}

	return hookTestOperand(words[len(words)-1])
}

func hookCleanupRedirect(r *shellsyntax.Redirect) bool {
	return r.Op == ">" && r.FD == "2" && hookDiscardedOutput(r)
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
	if r.Op != ">&" || (r.FD != "" && r.FD != "1") || fd != "2" {
		return false
	}

	for _, arg := range cmd.Words[1:] {
		if _, literal := arg.Literal(); !literal {
			return false
		}
	}

	return true
}
