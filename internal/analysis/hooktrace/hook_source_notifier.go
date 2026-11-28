package hooktrace

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

const hookNotifierExecutable = "\x00scout-terminal-notifier"

func hookNotifierLookup(tree *shellsyntax.File, state hookSourceState) bool {
	if tree == nil || len(tree.Statements) != 2 || state.lookupUnknown ||
		state.hasFunction("command") || state.hasFunction("terminal-notifier") || state.hasFunction("echo") {
		return false
	}

	probe, fallback := tree.Statements[0], tree.Statements[1]
	if probe.Next != shellsyntax.OrElse || hookAndOrLink(fallback.Next) || probe.Background || fallback.Background ||
		probe.Negated || fallback.Negated || len(probe.Commands) != 1 || len(fallback.Commands) != 1 {
		return false
	}

	lookup, output := probe.Commands[0], fallback.Commands[0]
	if len(lookup.Words) != 3 || len(output.Words) != 2 || len(lookup.Assignments) != 0 ||
		len(output.Assignments) != 0 || len(lookup.Redirects) != 0 || len(output.Redirects) != 0 {
		return false
	}

	command, _ := lookup.Words[0].Literal()
	probeOption, _ := lookup.Words[1].Literal()
	application, _ := lookup.Words[2].Literal()
	printer, _ := output.Words[0].Literal()
	executable, _ := output.Words[1].Literal()

	return command == "command" && probeOption == "-v" && application == "terminal-notifier" &&
		printer == "echo" && hookNotifierPath(executable)
}

func hookNotifierPath(value string) bool {
	switch value {
	case "/opt/homebrew/bin/terminal-notifier", "/usr/local/bin/terminal-notifier", "/usr/bin/terminal-notifier":
		return true
	default:
		return false
	}
}

func hookNotifierAction(words []*shellsyntax.Word) bool {
	if len(words) != 2 {
		return false
	}

	flag, _ := words[0].Literal()

	return flag == "-execute" && hookNotifierCommandWord(words[1])
}

func hookNotifierCommandWord(word *shellsyntax.Word) bool {
	if word.Writes || !hookFixedArgument(word) {
		return false
	}

	for _, part := range word.Parts {
		if part.Kind == shellsyntax.PartLiteral && strings.TrimSpace(part.Text) != "" {
			return true
		}
	}

	return false
}

func mergeNotifierOptions(first, second hookVariableFact) (hookVariableFact, bool) {
	if !first.notifierAction {
		first, second = second, first
	}

	if !first.notifierAction {
		return hookVariableFact{}, false
	}

	// The only other modeled alternative is a known empty array.
	if second.notifierAction || second.kind == hookDecimalArray && second.fixedArraySize == 1 {
		if first != second {
			first.fixedArraySize = 0
		}

		return first, true
	}

	return hookVariableFact{}, false
}

func (w *hookSourceWalk) traceTerminalNotifier(e *File, view source.View, cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || len(cmd.Words) < 3 || len(cmd.Assignments) != 0 ||
		slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) }) {
		return false
	}

	name, known := w.value(cmd.Words[0], state, false)
	if !known || state.hasFunction(name) || name != hookNotifierExecutable && name != "terminal-notifier" && !hookNotifierPath(name) {
		return false
	}

	if !w.hookNotifierArguments(cmd.Words[1:], state) {
		return false
	}

	w.recordHookCommandText(e, view, cmd.Span, false)
	w.commandGap(e, view, cmd.Span, "hook_source_notifier_scope_unverified",
		"The recorded notification action depends on the runtime notification program and a user click.")

	return true
}

func (w *hookSourceWalk) hookNotifierArguments(words []*shellsyntax.Word, state hookSourceState) bool {
	var message, action bool

	for len(words) > 0 {
		flag := words[0]
		if flagName, known := flag.Literal(); known {
			if len(words) < 2 || !hookFixedArgument(words[1]) || words[1].Writes {
				return false
			}

			switch flagName {
			case "-message":
				message = true
			case "-execute":
				action = action || hookNotifierCommandWord(words[1])
			case "-title", "-subtitle", "-sound", "-group", "-sender", "-activate":
			default:
				return false
			}

			words = words[2:]

			continue
		}

		if !state.explicitBash || len(flag.Parts) != 1 || flag.Parts[0].Kind != shellsyntax.PartParameterArrayAll ||
			!flag.Parts[0].Quoted || !state.kinds[flag.Parts[0].Text].notifierAction {
			return false
		}

		action = true
		words = words[1:]
	}

	return message && action
}

func (w *hookSourceWalk) recordHookCommandText(e *File, view source.View, span source.Span, hostUpdatedInput bool) {
	physical, err := view.Original(span)
	if err != nil {
		w.commandGap(e, view, span, "hook_source_command_unverified", "The hook command could not be mapped to captured source.")
		return
	}

	next, kept := e.Doc.WithTracedShellCommand(document.TracedShellCommand{Span: physical, HostUpdatedInput: hostUpdatedInput})

	*e.Doc = next
	if !kept {
		w.commandGap(e, view, span, "hook_source_limit", "The hook command evidence budget was exhausted.")
	}
}
