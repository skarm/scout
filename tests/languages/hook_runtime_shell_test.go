package scout_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

func TestClaudeHookBashInputRewrite(t *testing.T) {
	const jq = `jq --arg project "$PWD" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    updatedInput: (.tool_input | .command = "cd \($project | @sh); \(.command)")
  }
}' <<< "$payload"`

	for _, tc := range []struct {
		name, event, matcher, command string
		want                          bool
	}{
		{name: "Bash tool", event: "PreToolUse", matcher: "Edit|Bash", command: jq, want: true},
		{name: "other tool", event: "PreToolUse", matcher: "Edit", command: jq},
		{name: "other event", event: "Stop", matcher: "Bash", command: jq},
		{name: "redirected output", event: "PreToolUse", matcher: "Bash", command: jq + " >/dev/null"},
		{name: "substitution", event: "PreToolUse", matcher: "Bash", command: "result=$(" + jq + ")"},
		{name: "shadowed jq", event: "PreToolUse", matcher: "Bash", command: "jq() { :; }\n" + jq},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", fmt.Sprintf(
				`{"hooks":{"%s":[{"matcher":%q,"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/run.sh\""}]}]}}`, tc.event, tc.matcher))
			scenario.WriteFile(t, root, "run.sh", "payload=$(cat)\n"+tc.command+"\n")

			result, err := scenario.Scan(t, root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			count := 0
			for _, f := range result.Findings {
				if !slices.Contains(f.ContextSignals, check.ShellHostUpdatedInput) {
					continue
				}

				count++
				if f.RuleID != "SH003" || f.Location.Path != "run.sh" || f.Location.StartLine != 6 ||
					len(f.HookSources) != 1 || f.HookSources[0].Event != "PreToolUse" {
					t.Fatalf("incorrect Bash rewrite evidence: %+v", f)
				}
			}
			if (count == 1) != tc.want {
				t.Fatalf("observed %d Bash rewrites, want presence %v", count, tc.want)
			}
		})
	}
}

func TestShellHookTerminalNotifierAction(t *testing.T) {
	const lookup = `notifier=$(command -v terminal-notifier || echo /opt/homebrew/bin/terminal-notifier)`
	const invoke = `"$notifier" -message "$message" "${action[@]}" -sound Glass 2>/dev/null`
	const option = `action=()
[ -n "$click" ] && action=(-execute "printf ready")`

	for _, tc := range []struct {
		name, script string
		want         bool
	}{
		{name: "optional action", script: lookup + "\n" + option + "\n" + invoke, want: true},
		{name: "different executable", script: "notifier=printf\n" + option + "\n" + invoke},
		{name: "array overwritten", script: lookup + "\n" + option + "\naction=()\n" + invoke},
		{name: "array unused", script: lookup + "\n" + option + "\n" + `"$notifier" -message 'help -execute printf'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/run.sh\""}]}]}}`)
			scenario.WriteFile(t, root, "run.sh", tc.script+"\n")

			result, err := scenario.Scan(t, root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			count := 0
			for _, f := range result.Findings {
				if f.RuleID == "SH003" && f.Location.Path == "run.sh" && slices.Contains(f.ContextSignals, check.ShellCommandText) {
					count++
					if len(f.HookSources) != 1 || f.HookSources[0].Event != "Stop" {
						t.Fatalf("incorrect notification action source: %+v", f)
					}
				}
			}
			if (count == 1) != tc.want {
				t.Fatalf("observed %d notification actions, want presence %v", count, tc.want)
			}
		})
	}
}

func TestShellHookArithmeticFallbackKeepsCallContext(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
	scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/run.sh\""}]}]}}`)
	scenario.WriteFile(t, root, "run.sh", `clips=()
for dir in "$HOME/media" "$HOME/sounds"; do
  for f in "$dir"/*.wav; do [ -f "$f" ] && clips+=("$f"); done
  [ "${#clips[@]}" -gt 0 ] && break
done
play() {
  powershell.exe -Command "Write-Output ready"
}
if [ "${#clips[@]}" -gt 0 ]; then
  mkdir -p "$HOME/state" 2>/dev/null
  i="$(cat "$HOME/state/index" 2>/dev/null || echo -1)"
  case "$i" in ''|*[!0-9]*) i=-1 ;; esac
  i=$(( (i + 1) % ${#clips[@]} ))
  play "${clips[$i]}" >/dev/null 2>&1
fi
`)

	result, err := scenario.Scan(t, root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	for _, f := range result.Findings {
		if f.Location.Path == "run.sh" && f.Location.StartLine == 7 && f.RuleID == "SH003" &&
			len(f.HookSources) == 1 && f.HookSources[0].Event == "Stop" && len(f.HookSources[0].Steps) == 2 &&
			f.HookSources[0].Steps[1].StartLine == 14 && slices.Contains(f.ContextSignals, check.ShellCommandText) {
			return
		}
	}

	t.Fatal("missing hook context for the PowerShell command reached through the arithmetic fallback")
}
