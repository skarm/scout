package shell

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

// Inspect the fallback when timeout is optional. Its probe can fail, leaving
// the unquoted prefix empty and the interpreter in the command position.
func (a *shellWalk) optionalTimeoutCommand(stmts []*shellsyntax.Statement, s *shellState) {
	prefix, body := timeoutFallback(stmts, s)

	cmd := timeoutInvocation(prefix, body, s)
	if cmd != nil {
		a.emit(ruleSH003, cmd.Span, nil, check.ShellCommandText)
	}
}

func timeoutFallback(stmts []*shellsyntax.Statement, s *shellState) (string, []*shellsyntax.Statement) {
	start := timeoutAssignment(stmts[0])
	update := timeoutAssignment(stmts[2])

	launch := timeoutAssignment(stmts[3])
	if start == nil || update == nil || launch == nil || start.Name != update.Name ||
		!timeoutListEnd(stmts[0].Next) || stmts[1].Next != "&&" || !timeoutListEnd(stmts[2].Next) ||
		s.functions["command"] != nil || s.functions["timeout"] != nil {
		return "", nil
	}

	initial, known := start.Value.Literal()
	if !known || initial != "" || len(update.Value.Parts) == 0 || len(launch.Value.Parts) != 1 {
		return "", nil
	}

	prefix, output := update.Value.Parts[0], launch.Value.Parts[0]
	if prefix.Kind != "literal" || !strings.HasPrefix(prefix.Text, "timeout ") ||
		output.Kind != "substitution" || output.Tree == nil {
		return "", nil
	}

	probe := timeoutSimpleCommand(stmts[1])
	if probe == nil || !timeoutLiteralWords(probe.Words, "command", "-v", "timeout") ||
		len(probe.Assignments) != 0 || !timeoutDiscardedOutput(probe) {
		return "", nil
	}

	return start.Name, output.Tree.Statements
}

func timeoutInvocation(prefix string, body []*shellsyntax.Statement, s *shellState) *shellsyntax.Command {
	if len(body) == 2 && timeoutDirectoryGuard(body[0], s) {
		body = body[1:]
	}

	if len(body) != 1 || !timeoutListEnd(body[0].Next) {
		return nil
	}

	cmd := timeoutSimpleCommand(body[0])
	if cmd == nil || len(cmd.Assignments) != 0 || len(cmd.Words) < 4 {
		return nil
	}

	head := cmd.Words[0]
	if len(head.Parts) != 1 || head.Writes || head.Expands {
		return nil
	}

	param := head.Parts[0]
	if param.Kind != "parameter" || !param.PlainParameter || param.Quoted || param.Text != prefix {
		return nil
	}

	name, known := cmd.Words[1].Literal()
	if !known || s.functions[name] != nil || !isShellInterpreter(name) {
		return nil
	}

	args := cmd.Words[2:]

	index, _ := shellsyntax.CommandTextIndex(len(args), func(i int) (string, bool) {
		return args[i].Literal()
	}, true)
	if index < 0 {
		return nil
	}

	word := args[index]
	if text, fixed := word.Literal(); fixed && strings.TrimSpace(text) == "" {
		return nil
	}

	if word.Quoted && !word.Writes {
		return cmd
	}

	return nil
}

func timeoutListEnd(next string) bool {
	return next == "" || next == ";" || next == "newline"
}

func timeoutAssignment(stmt *shellsyntax.Statement) *shellsyntax.Assignment {
	cmd := timeoutSimpleCommand(stmt)
	if cmd == nil || len(cmd.Assignments) != 1 || len(cmd.Words) != 0 || len(cmd.Redirects) != 0 {
		return nil
	}

	assignment := &cmd.Assignments[0]
	if assignment.Value == nil || assignment.Value.Writes {
		return nil
	}

	return assignment
}

func timeoutSimpleCommand(stmt *shellsyntax.Statement) *shellsyntax.Command {
	if stmt.Negated || stmt.Background || stmt.Next == "&" || len(stmt.Commands) != 1 {
		return nil
	}

	cmd := stmt.Commands[0]
	if cmd.Declaration != "" || cmd.Group != nil || cmd.Subshell != nil || cmd.FunctionName != "" ||
		len(cmd.Alternatives) != 0 || len(cmd.Invalidates) != 0 {
		return nil
	}

	return cmd
}

func timeoutLiteralWords(words []*shellsyntax.Word, values ...string) bool {
	return slices.EqualFunc(words, values, func(word *shellsyntax.Word, want string) bool {
		value, known := word.Literal()
		return known && value == want
	})
}

func timeoutDirectoryGuard(stmt *shellsyntax.Statement, s *shellState) bool {
	cmd := timeoutSimpleCommand(stmt)

	return stmt.Next == "&&" && cmd != nil && len(cmd.Assignments) == 0 && len(cmd.Words) == 2 &&
		timeoutLiteralWords(cmd.Words[:1], "cd") && s.functions["cd"] == nil &&
		cmd.Words[1].Quoted && !cmd.Words[1].Writes && timeoutDiscardedOutput(cmd)
}

func timeoutDiscardedOutput(cmd *shellsyntax.Command) bool {
	for _, redirect := range cmd.Redirects {
		if redirect.Op != ">" && redirect.Op != ">&" {
			return false
		}

		target, known := redirect.Target.Literal()
		if !known || redirect.Op == ">" && target != "/dev/null" ||
			redirect.Op == ">&" && (redirect.FD != "2" || target != "1") {
			return false
		}
	}

	return true
}
