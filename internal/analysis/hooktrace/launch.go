package hooktrace

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/report"
)

// ShellLink classifies when a prepared hook can be linked in the component graph.
func ShellLink(tree parse.ShellTree, host string, projectSettings, hasPaths bool) (inline, file bool) {
	if tree.ExecutionError == nil && literalInlineHook(tree.Tree) {
		return true, false
	}

	if !hasPaths {
		return false, false
	}

	shell := hookSourceTree(tree)
	_, simple := SimpleShellCommand(shell)

	return false, guardedShellLaunch(shell, host) || projectSettings && simple && !shell.OmittedExecution
}

// RootedSuffix extracts a path under the plugin root from argv or a symbolic shell word.
func RootedSuffix(value, host string, argv, hook bool) (string, bool) {
	if argv {
		return literalRootSuffix(value, host, hook)
	}

	return strings.CutPrefix(value, pluginRootMarker)
}

//nolint:gochecknoglobals // Read-only root parameter grammar for supported hosts.
var pluginRootParameters = map[string]string{
	report.HostClaudeCode: "CLAUDE_PLUGIN_ROOT", report.HostCodex: "PLUGIN_ROOT",
	report.HostCursor: "CURSOR_PLUGIN_ROOT", report.HostCopilotCLI: "PLUGIN_ROOT",
}

// Codex exports this compatibility name for commands of installed plugin hooks.
const codexHookRootAlias = "CLAUDE_PLUGIN_ROOT"

func rootParameter(host, name string, hook bool) bool {
	if host == report.HostGrokCLI {
		return hook && (name == "GROK_PLUGIN_ROOT" || name == codexHookRootAlias)
	}

	return name != "" && (name == pluginRootParameters[host] ||
		name == codexHookRootAlias && (hook && host == report.HostCodex || host == report.HostCursor || host == report.HostCopilotCLI) ||
		host == report.HostCopilotCLI && name == "COPILOT_PLUGIN_ROOT")
}

// A literal data-emitting Bash builtin is the handler itself. No handler
// file needs to be found, and its quoted argument is data even if it mentions
// a shell command.
func literalInlineHook(tree *shellsyntax.File) bool {
	cmd, simple := SimpleShellCommand(tree)
	if !simple || tree.Statements[0].Negated || tree.Statements[0].Background {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	switch name {
	case ":", "true", "false", "echo":
	case "printf":
		if hookPrintfMayWrite(cmd.Words[1:]) {
			return false
		}
	default:
		return false
	}

	for _, arg := range cmd.Words[1:] {
		if _, literal := arg.Literal(); !literal {
			return false
		}
	}

	return true
}

func guardedShellLaunch(tree *shellsyntax.File, host string) bool {
	if tree == nil || len(tree.Statements) != 2 {
		return false
	}

	guard, launch := tree.Statements[0], tree.Statements[1]
	if guard.Next != shellsyntax.AndThen || guard.Background || launch.Background || launch.Negated ||
		!simpleHookCommand(guard, "cd") || len(launch.Commands) != 1 {
		return false
	}

	cd, script := guard.Commands[0], launch.Commands[0]
	if len(cd.Words) != 2 || len(script.Words) < 2 || len(script.Assignments) != 0 || len(script.Redirects) != 0 {
		return false
	}

	root, known := SymbolicWord(cd.Words[1], host, true)
	name, literal := script.Words[0].Literal()

	return known && cd.Words[1].Quoted && root == pluginRootValue && literal && IsShellInterpreter(name) &&
		len(hookSourceOperands(script.Words, name)) > 0
}

// SimpleShellCommand extracts a single command without shell composition.
func SimpleShellCommand(tree *shellsyntax.File) (*shellsyntax.Command, bool) {
	if tree == nil || len(tree.Statements) != 1 || len(tree.Statements[0].Commands) != 1 {
		return nil, false
	}

	statement := tree.Statements[0]

	command := statement.Commands[0]
	if len(command.Assignments) != 0 || len(command.Redirects) != 0 || command.Subshell != nil || len(command.Words) == 0 || slices.Contains([]string{"&", "&&", "||"}, statement.Next) {
		return nil, false
	}

	return command, true
}

func literalRootSuffix(value, host string, hook bool) (string, bool) {
	parameter, found := strings.CutPrefix(value, "${")
	if !found {
		return "", false
	}

	name, suffix, found := strings.Cut(parameter, "}/")

	return suffix, found && rootParameter(host, name, hook)
}

// SymbolicWord expands only the supported plugin root parameters.
func SymbolicWord(w *shellsyntax.Word, host string, hook bool) (string, bool) {
	if w == nil || w.Expands {
		return "", false
	}

	var b strings.Builder

	for _, part := range w.Parts {
		switch part.Kind {
		case shellsyntax.PartLiteral:
			b.WriteString(part.Text)
		case shellsyntax.PartParameter, shellsyntax.PartParameterDefaultDot:
			if rootParameter(host, part.Text, hook) {
				b.WriteString(pluginRootValue)
			} else {
				return "", false
			}
		default:
			return "", false
		}
	}

	return b.String(), true
}
