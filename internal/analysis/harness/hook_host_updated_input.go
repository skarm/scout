package harness

import (
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// Match the complete jq response in which the current Bash tool input is
// copied and its command is prefixed using a shell-escaped jq string binding.
// Reject other filters, writes and string escapes instead of guessing jq flow.
var claudeUpdatedInputFilter = regexp.MustCompile(
	`^\s*\{\s*hookSpecificOutput\s*:\s*\{\s*hookEventName\s*:\s*"PreToolUse"\s*,\s*` +
		`permissionDecision\s*:\s*"(?:allow|ask)"\s*,\s*` +
		`(?:permissionDecisionReason\s*:\s*"(?:[^"\\]|\\["\\/bfnrt])*"\s*,\s*)?` +
		`updatedInput\s*:\s*\(\s*\.tool_input\s*\|\s*\.command\s*=\s*` +
		`"([^"\\]+)\\\(\$([A-Za-z_][A-Za-z_0-9]*)\s*\|\s*@sh\)([^"\\]*)\\\(\.command\)"\s*\)\s*\}\s*\}\s*$`,
)

func (w *hookSourceWalk) initialHookSourceState(shell *shellsyntax.File, hook *jsonconfig.Node, matcher string, wholeCommand bool) hookSourceState {
	var state hookSourceState
	if wholeCommand {
		w.seedHostEnvironment(&state)

		if w.plugin.projectSettings {
			state.bindValue("CLAUDE_PROJECT_DIR", pluginRootValue, true)
		}

		_, simple := simpleShellCommand(shell)
		state.hookOutput = simple && w.claudeBashHookOutput(hook, matcher)
	}

	return state
}

func (w *hookSourceWalk) claudeBashHookOutput(hook *jsonconfig.Node, matcher string) bool {
	if w.plugin.host != report.HostClaudeCode || w.plugin.activation == "inactive_for_profile" ||
		w.event != "PreToolUse" || hook.Get("if") != nil || hook.Get("async") != nil ||
		hook.Get("asyncRewake") != nil || hook.Get("background") != nil {
		return false
	}

	if matcher == "" || matcher == "*" {
		return true
	}

	for tool := range strings.SplitSeq(matcher, "|") {
		if tool == "Bash" {
			return true
		}
	}

	return false
}

func hookKeepsOutput(redirects []*shellsyntax.Redirect) bool {
	for _, redirect := range redirects {
		if redirect.FD == shellsyntax.StderrFD && redirect.Op == shellsyntax.RedirectOutput && hookDiscardedOutput(redirect) || hookStdinRedirect(redirect) {
			continue
		}

		return false
	}

	return true
}

func (w *hookSourceWalk) traceHostUpdatedInput(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState) bool {
	if !state.hookOutput || state.lookupUnknown || state.hasFunction("jq") ||
		len(cmd.Words) != 5 || len(cmd.Assignments) != 0 || !hookKeepsOutput(cmd.Redirects) {
		return false
	}

	input := false
	for _, redirect := range cmd.Redirects {
		if redirect.Op == shellsyntax.RedirectHereString && !input && (redirect.FD == "" || redirect.FD == shellsyntax.StdinFD) && hookFixedArgument(redirect.Target) {
			input = true
			continue
		}

		if redirect.FD != shellsyntax.StderrFD || redirect.Op != shellsyntax.RedirectOutput || !hookDiscardedOutput(redirect) {
			return false
		}
	}

	name, _ := cmd.Words[0].Literal()
	option, _ := cmd.Words[1].Literal()
	key, _ := cmd.Words[2].Literal()

	filter, fixed := cmd.Words[4].Literal()
	if !input || name != "jq" || option != "--arg" || !hookVariableName(key) ||
		!hookSingleBracketWord(cmd.Words[3]) || !fixed || len(filter) > maxHookSourceValue {
		return false
	}

	parts := claudeUpdatedInputFilter.FindStringSubmatchIndex(filter)
	if len(parts) != 8 || filter[parts[4]:parts[5]] != key ||
		strings.TrimSpace(filter[parts[2]:parts[3]]+filter[parts[6]:parts[7]]) == "" {
		return false
	}

	span := cmd.Words[4].Span
	if view.Text()[span.Start:span.End] == "'"+filter+"'" {
		start := span.Start + 1 + strings.LastIndex(filter[:parts[2]], ".command")
		span = source.Span{Start: start, End: start + len(".command")}
	}

	w.recordHookCommandText(e, view, span, true)
	w.commandGap(e, view, cmd.Span, "hook_source_updated_input_scope_unverified",
		"The recorded Bash input rewrite depends on the host accepting the hook response.")

	return true
}
