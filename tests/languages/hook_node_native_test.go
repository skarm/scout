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
		{name: "temporary environment for inline Node", wrapper: "if MODE=\"$mode\" node -e \"process.exit(0)\" 2>/dev/null; then\n  node \"$1\"\nfi", want: true},
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

func TestHookCommonJSDispatchLinksOnlyCalledExports(t *testing.T) {
	for _, tc := range []struct {
		name, call string
		want       bool
	}{
		{name: "called export", call: "handler.run()", want: true},
		{name: "inactive branch", call: "if (false) handler.run()"},
		{name: "short circuit and", call: "false && handler.run()"},
		{name: "short circuit or", call: "true || handler.run()"},
		{name: "short circuit nullish", call: "false ?? handler.run()"},
		{name: "inactive ternary branch", call: "true ? null : handler.run()"},
		{name: "active ternary branch", call: "false ? null : handler.run()", want: true},
		{name: "helper reassigned", call: "function invoke() { handler.run() }; invoke = () => {}; invoke()"},
		{name: "helper reassigned in block", call: "function invoke() { handler.run() }; if (true) { invoke = () => {} }; invoke()"},
		{name: "block shadow keeps outer helper", call: "function invoke() { handler.run() }; { const invoke = () => {}; invoke() }; invoke()", want: true},
		{name: "second helper call uses its argument", call: "function invoke(target) { target.run() }; invoke({run() {}}); invoke(handler)", want: true},
		{name: "shadowed binding", call: "{ const handler = {run() {}}; handler.run(); }"},
		{name: "not called", call: "console.log(handler.run)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, ".claude-plugin/plugin.json", `{"name":"test-plugin"}`)
			scenario.WriteFile(t, root, "hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"node \"${CLAUDE_PLUGIN_ROOT}/dispatch.cjs\" inspect"}]}]}}`)
			scenario.WriteFile(t, root, "dispatch.cjs", `const path = require('node:path');
const fs = require('node:fs');
function resolve(name) {
  const candidate = path.join(__dirname, `+"\x60${name}.cjs\x60"+`);
  if (fs.existsSync(candidate)) return candidate;
  return null;
}
function main() {
  const name = process.argv[2];
  const filename = resolve(name);
  const handler = require(filename);
  `+tc.call+`
}
main();
`)
			scenario.WriteFile(t, root, "inspect.cjs", `const {execute} = require('./utils.cjs');
function run() { execute(); }
module.exports = {run};
`)
			scenario.WriteFile(t, root, "utils.cjs", `const {execSync} = require('node:child_process');
function execute() { execSync('printf ready'); }
function unused() { execSync('printf unused'); }
module.exports = {execute, unused};
`)

			result, err := scenario.Scanner(t, scantest.FullConfig()).Scan(t.Context(), root)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			count := 0
			for _, f := range result.Findings {
				if f.RuleID != "JS001" || f.Location.Path != "utils.cjs" || len(f.HookSources) == 0 ||
					!slices.Contains(f.ContextSignals, check.ShellCommandText) {
					continue
				}

				count++
				steps := f.HookSources[0].Steps
				if f.Location.StartLine != 2 || len(steps) != 3 || steps[0].Path != "hooks/hooks.json" ||
					steps[1].Path != "dispatch.cjs" || steps[2].Path != "inspect.cjs" {
					t.Fatalf("incorrect CommonJS call path: %+v", f)
				}
			}

			if (count == 1) != tc.want {
				t.Fatalf("linked %d CommonJS findings, want presence %v", count, tc.want)
			}
		})
	}
}
