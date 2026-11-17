//go:build !coreonly && cgo

package scout_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/report"
)

func TestHookNodeWrapperLinksShellCommandText(t *testing.T) {
	for _, tc := range []struct {
		name, wrapper string
		want          bool
	}{
		{name: "argv forwarded through env", wrapper: `exec env -i HOME="$HOME" PATH="$PATH" node "$@"`, want: true},
		{name: "known script operand", wrapper: `node "$1"`, want: true},
		{name: "literal path in a shell option", wrapper: `node --eval "$1"`},
		{name: "shadowed node command", wrapper: "node() { :; }\nnode \"$1\""},
		{name: "env launches an external command", wrapper: "node() { :; }\nenv -i node \"$1\"", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/wrap.sh\" \"${CLAUDE_PLUGIN_ROOT}/handler.cjs\""}]}]}}`)
			scenario.WriteFile(t, root, "wrap.sh", tc.wrapper+"\n")
			scenario.WriteFile(t, root, "handler.cjs", `
const {execSync, execFileSync} = require('node:child_process');
execSync('printf ready');
execFileSync('/bin/sh', ['-n', 'example.sh']);
`)

			result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			observed := slices.ContainsFunc(result.Findings, func(f report.Finding) bool {
				return f.RuleID == "JS001" && f.Location.Path == "handler.cjs" &&
					slices.Contains(f.ContextSignals, check.ShellCommandText) &&
					slices.ContainsFunc(f.HookSources, func(h report.HookSourceContext) bool {
						return h.Event == "SessionStart" && len(h.Steps) == 2 &&
							h.Steps[0].Path == "hooks/hooks.json" && h.Steps[1].Path == "wrap.sh"
					})
			})
			if observed != tc.want {
				t.Fatalf("linked Node command text = %v, want %v: %+v", observed, tc.want, result.Findings)
			}

			if slices.ContainsFunc(result.Findings, func(f report.Finding) bool {
				return f.RuleID == "JS001" && f.Location.Path == "handler.cjs" && f.Location.StartLine == 4 &&
					slices.Contains(f.ContextSignals, check.ShellCommandText)
			}) {
				t.Fatal("execFileSync without shell command text was counted as a command string")
			}

			if tc.want && (result.Coverage.ShellHooks == nil ||
				!slices.Contains(result.Coverage.ShellHooks.Gaps, "hook_source_node_scope_unverified")) {
				t.Fatalf("expected explicit Node runtime coverage gap: %+v", result.Coverage.ShellHooks)
			}
		})
	}
}
