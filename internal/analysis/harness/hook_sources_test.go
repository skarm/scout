package harness_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestHookPathsWithDefaultRootAndGuardedDirectory(t *testing.T) {
	for _, command := range []string{
		`bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`,
		`bash "${CLAUDE_PLUGIN_ROOT:-.}/start.sh"`,
		`cd "$CLAUDE_PLUGIN_ROOT" && bash ./start.sh`,
	} {
		graph, docs, hooks := inspectShellHook(t, command, "bash", "set -euo pipefail\nsource \"${CLAUDE_PLUGIN_ROOT:-.}/helper\"\n", false)
		assertHookTerminalPath(t, hooks, "p/helper")
		if !hasReference(graph, "resolved", "captured_handler_not_runtime_proof") ||
			!hasReference(graph, "unresolved", "runtime_not_materialized") {
			t.Fatalf("missing captured handler or runtime boundary: %+v", graph.References)
		}
		for _, doc := range docs {
			if doc.Artifact().Metadata().Path == "p/helper" && doc.Classification().Basis != "hook-source" {
				t.Fatalf("captured extensionless helper lacks a shell classification: %+v", doc.Classification())
			}
		}
	}
}

func TestUnquotedPluginLaunchTracesCandidateAndKeepsGap(t *testing.T) {
	for _, command := range []string{`${CLAUDE_PLUGIN_ROOT}/start.sh`, `bash ${CLAUDE_PLUGIN_ROOT}/start.sh`} {
		_, _, hooks := inspectShellHook(t, command, "bash", "#!/bin/bash\nprintf ready\n", true)
		if len(hooks.Paths) != 1 || hooks.Paths[0].Target != "p/start.sh" ||
			len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_unquoted_root" {
			t.Fatalf("unquoted launch %q: %+v", command, hooks)
		}
	}
}

func TestUnquotedPluginRootRequiresBothShellGuards(t *testing.T) {
	for _, tc := range []struct {
		name, commands string
		reaches        bool
	}{
		{"source", "IFS=\nset -f\nsource ${PLUGIN_ROOT}/lib.sh", true},
		{"interpreter", "IFS=''\nset -o noglob\nbash $PLUGIN_ROOT/lib.sh", true},
		{"exec interpreter", "IFS=\nset -uf\nexec bash $PLUGIN_ROOT/lib.sh", true},
		{"glob still enabled", "IFS=\nbash $PLUGIN_ROOT/lib.sh", false},
		{"splitting still enabled", "set -f\nbash $PLUGIN_ROOT/lib.sh", false},
		{"glob re-enabled", "IFS=\nset -f\nset +f\nbash $PLUGIN_ROOT/lib.sh", false},
		{"separator changed", "IFS=\nset -f\nIFS=/\nbash $PLUGIN_ROOT/lib.sh", false},
		{"branch does not guarantee guard", "IFS=\nif [ -e ./paths.sh ]; then set -f; fi\nbash $PLUGIN_ROOT/lib.sh", false},
		{"function sets guard", "guard() { IFS=; set -f; }\nguard\nsource $PLUGIN_ROOT/lib.sh", true},
		{"function background cannot set guard", "IFS=\nset -f &\nbash $PLUGIN_ROOT/lib.sh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, tc.commands+"\n", "")
			if tc.reaches {
				assertHookTerminalPath(t, hooks, "p/lib.sh")
			} else if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_unquoted_root" {
				t.Fatalf("expected unquoted root with unresolved expansion: %+v", hooks)
			}
		})
	}
}

func TestUnquotedPluginHookTemplateKeepsExpansionGap(t *testing.T) {
	const launch = "IFS=; set -f; bash ${CLAUDE_PLUGIN_ROOT}/start.sh"
	_, _, hooks := inspectShellHook(t, launch, "bash", "#!/bin/bash\nprintf ready\n", true)
	if len(hooks.Paths) != 1 || hooks.Paths[0].Target != "p/start.sh" ||
		len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_unquoted_root" {
		t.Fatalf("host interpolation was treated as guarded shell expansion: %+v", hooks)
	}
}

func TestShellSafeRootIsScopedToSimpleHookLaunchAndHost(t *testing.T) {
	const handler = "#!/bin/bash\nprintf ready\n"
	for _, tc := range []struct {
		name, command, host, path, script string
		wantGap                           bool
	}{
		{"direct", "${CLAUDE_PLUGIN_ROOT}/start.sh", report.HostClaudeCode, "/scout/plugin", handler, false},
		{"interpreter", "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", report.HostClaudeCode, "/scout/plugin", handler, false},
		{"other host", "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", report.HostCodex, "/scout/plugin", handler, true},
		{"changed splitting", "IFS=/; bash $CLAUDE_PLUGIN_ROOT/start.sh", report.HostClaudeCode, "/scout/plugin", handler, true},
		{"inside script", "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", report.HostClaudeCode, "/scout/plugin", "bash ${CLAUDE_PLUGIN_ROOT}/helper\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: tc.host, Path: tc.path}}
			_, _, hooks := inspectShellHookWithOptions(t, options, tc.command, "bash", tc.script, true)
			gotGap := slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == "hook_source_unquoted_root" })
			if gotGap != tc.wantGap || len(hooks.Paths) == 0 || hooks.Paths[0].Target != "p/start.sh" {
				t.Fatalf("unexpected source paths or gaps: %+v", hooks)
			}
		})
	}
}

func TestCodexPluginHooksUseCompatibilityRoot(t *testing.T) {
	const launch = `bash ${CLAUDE_PLUGIN_ROOT}/start.sh`
	const handler = `source "${CLAUDE_PLUGIN_ROOT}/helper"`

	codex := artifact.NewFile("p/.codex-plugin/plugin.json", []byte(`{"name":"example"}`), false)
	for _, host := range []string{report.HostClaudeCode, report.HostAuto} {
		t.Run(host, func(t *testing.T) {
			o := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: host, Path: "/scout/plugin"}}
			graph, _, hooks := inspectShellHookWithOptions(t, o, launch, "bash", handler, true, codex)
			if !hasReference(graph, "resolved", "captured_handler_not_runtime_proof") || len(hooks.Paths) != 4 {
				t.Fatalf("expected both hosts to trace the captured handler and its source: %+v", hooks)
			}

			wantUnquoted := host == report.HostClaudeCode
			if got := slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == "hook_source_unquoted_root" }); got != wantUnquoted {
				t.Fatalf("wrong root proof for %s: %+v", host, hooks.Diagnostics)
			}
		})
	}
}

func TestHookLocaleIsAnExplicitFirstScriptAssumption(t *testing.T) {
	const handler = `count=$(cat runtime.txt)
[[ ! "$count" =~ ^[0-9]+$ ]] && exit 0
grep -q ready runtime.txt 2>/dev/null || exit 0
next=$((count + 1))
source "${CLAUDE_PLUGIN_ROOT}/helper"
`

	for _, tc := range []struct{ locale, prefix string }{
		{"", ""},
		{"C", ""},
		{"C", "LC_ALL=\"$requested_locale\"\n"},
	} {
		o := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: report.HostClaudeCode, Path: "/scout/plugin", LCAll: tc.locale}}
		_, _, hooks := inspectShellHookWithOptions(t, o, `bash ${CLAUDE_PLUGIN_ROOT}/start.sh`, "bash", tc.prefix+handler, true)
		if tc.locale == "C" && tc.prefix == "" {
			assertHookTerminalPath(t, hooks, "p/helper")
		} else if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == "hook_source_command_unverified" }) {
			t.Fatalf("numeric range was accepted without a verified locale: %+v", hooks)
		}
	}
}

func TestHookExecRecordsUnverifiedRuntimeWithCapturedOperand(t *testing.T) {
	const handler = `runner=$(command -v other-runtime 2>/dev/null)
dir="$(cd "$(dirname "$0")" && pwd)"
exec "$runner" "$dir/main.ts"
`
	main := artifact.NewFile("p/main.ts", []byte("console.log('hello')\n"), false)
	_, _, hooks := inspectShellHook(t, `sh "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "sh", handler, false, main)
	if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_exec_runtime_unverified" {
		t.Fatalf("missing distinction between the captured operand and executor: %+v", hooks)
	}
}

func TestHookReadLoopExportIsBoundByCaseAndLocale(t *testing.T) {
	const handler = `helper="${CLAUDE_PLUGIN_ROOT}/helper"
while IFS='=' read -r key value || [[ -n "$key" ]]; do
  case "$key" in @NAMES@) export "$key"="$value" ;; esac
done < "$env_file"
source "$helper"
`
	for _, tc := range []struct {
		name, locale, names, gap string
	}{
		{"whitelist only", "C", "APP_LABEL|APP_TAG", ""},
		{"no locale proof", "", "APP_LABEL|APP_TAG", "hook_source_control_unverified"},
		{"lookup variable", "C", "APP_LABEL|pAtH", "hook_source_control_unverified"},
		{"case folded write", "C", "HELPER", "hook_source_dynamic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: report.HostClaudeCode, Path: "/scout/plugin", LCAll: tc.locale}}
			_, _, hooks := inspectShellHookWithOptions(t, opts, "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", "bash",
				strings.ReplaceAll(handler, "@NAMES@", tc.names), true)
			if tc.gap == "" {
				assertHookTerminalPath(t, hooks, "p/helper")
			} else if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == tc.gap }) {
				t.Fatalf("missing unresolved guard or binding: %+v", hooks)
			}
		})
	}
}

func TestHookFileOperationsPreservePhaseValidation(t *testing.T) {
	const handler = `human=false
if [ -f state.json ]; then
  jq -e 'has("phase") and has("status")' state.json >/dev/null 2>&1 || exit 0
  printf '%s\n' "$checksum" | cut -d' ' -f1 > state.sha256
fi
phase=$(cat phase.txt)
if [ -n "$phase" ] && ! [[ "$phase" =~ ^[0-9]+$ ]]; then phase=""; fi
if [ -f handoff.md ]; then mv handoff.md handoff.done 2>/dev/null || true; fi
next=$((${phase:-0} + 1))
if [ "$human" = true ]; then ignored=$((unknown + 1)); fi
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
	opts := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: report.HostClaudeCode, Path: "/scout/plugin", LCAll: "C"}}
	_, _, hooks := inspectShellHookWithOptions(t, opts, "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")
	if len(hooks.Diagnostics) != 0 {
		t.Fatalf("verified phase handling left gaps: %+v", hooks)
	}
}

func TestReadLoopArithmeticRequiresAnIterationGuard(t *testing.T) {
	const handler = `while IFS=: read -r line_num _; do
  @GUARD@
  @UPDATE@
  chunk=$(sed -n "${line_num},$((line_num + 8))p" lessons.txt 2>/dev/null || echo "")
done <<< "$runtime_lines"
@AFTER@
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
	for _, tc := range []struct {
		name, locale, guard, update, after string
		gapLine                            int
	}{
		{"guard skips invalid records", "C", `[[ "$line_num" =~ ^[0-9]+$ ]] || continue`, "", "", 0},
		{"explicit digits do not need a locale proof", "", `[[ "$line_num" =~ ^[0123456789]+$ ]] || continue`, "", "", 0},
		{"negated guard skips invalid records", "C", `[[ ! "$line_num" =~ ^[0-9]+$ ]] && continue`, "", "", 0},
		{"wrong branch skips valid records", "C", `[[ "$line_num" =~ ^[0-9]+$ ]] && continue`, "", "", 4},
		{"range depends on locale", "", `[[ "$line_num" =~ ^[0-9]+$ ]] || continue`, "", "", 4},
		{"reassigned operand", "C", `[[ "$line_num" =~ ^[0-9]+$ ]] || continue`, `line_num="$unchecked"`, "", 4},
		{"fact is local to the iteration", "C", `[[ "$line_num" =~ ^[0-9]+$ ]] || continue`, "", "next=$((line_num + 1))", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := report.HarnessOptions{ShellHookRoot: report.ShellHookRoot{Host: report.HostClaudeCode, Path: "/scout/plugin", LCAll: tc.locale}}
			script := strings.NewReplacer("@GUARD@", tc.guard, "@UPDATE@", tc.update, "@AFTER@", tc.after).Replace(handler)
			_, _, hooks := inspectShellHookWithOptions(t, opts, "bash ${CLAUDE_PLUGIN_ROOT}/start.sh", "bash", script, true)
			if tc.gapLine == 0 {
				assertHookTerminalPath(t, hooks, "p/helper")
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("verification rejected guarded numeric input: %+v", hooks.Diagnostics)
				}

				return
			}

			if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_command_unverified" ||
				hooks.Diagnostics[0].Line != tc.gapLine {
				t.Fatalf("expected an unverified arithmetic operand at line %d: %+v", tc.gapLine, hooks.Diagnostics)
			}
		})
	}
}

func TestReadLoopFunctionEffectsAcrossIterations(t *testing.T) {
	const handler = `count=0
process() {
  local field=$(printf '%s' "$1")
  @UPDATE@
}
while IFS= read -r line; do process "$line"; done <<< "$runtime_lines"
next=$((count + 1))
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
	for _, tc := range []struct {
		name, update, gap string
	}{
		{"counter stays numeric", "((count++))", ""},
		{"counter can become text", `count="$field"`, "hook_source_command_unverified"},
		{"callback may change the next read", "read() { :; }", "hook_source_control_unverified"},
		{"callback may break the caller loop", "break", "hook_source_control_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := strings.ReplaceAll(handler, "@UPDATE@", tc.update)
			_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", script, true)
			if tc.gap == "" {
				assertHookTerminalPath(t, hooks, "p/helper")
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("confirmed counter invariant left gaps: %+v", hooks.Diagnostics)
				}

				return
			}

			if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == tc.gap }) {
				t.Fatalf("missing unverified loop effect: %+v", hooks)
			}
		})
	}
}

func TestUnquotedPluginRootCanDispatchExecutableWithGuards(t *testing.T) {
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash",
		"IFS=\nset -f\nexec $CLAUDE_PLUGIN_ROOT/child.sh\n", true,
		artifact.NewFile("p/child.sh", []byte("#!/bin/sh\nprintf ready\n"), true))
	assertHookTerminalPath(t, hooks, "p/child.sh")
}

func TestHookSourceBoundedControlAndCommandEffects(t *testing.T) {
	for _, tc := range []struct {
		name, script, gap string
	}{
		{"redirected group with nested pipeline", `{
  for status in ready waiting; do
    case $status in ready) echo ready ;; esac
    printf '%s\n' "$status" | while read -r item; do
      [ -n "$item" ] && echo "$item"
    done
  done
} > report.txt
source ./lib.sh
`, ""},
		{"loop with status helper", `is_root() {
  local dir="$1"
  for candidate in "$dir"/*.txt; do
    [ -f "$candidate" ] && return 0
  done
  return 1
}
while [ -n "$project_dir" ]; do
  is_root "$project_dir" && break
  project_dir=
done
source ./lib.sh
`, ""},
		{"file descriptor and exit status", `if [[ -t 0 ]] || [[ $? -ne 0 ]]; then echo optional; fi
source ./lib.sh
`, ""},
		{"single brackets accept unquoted status and argument count", `if [ $? -ne 0 ] || [ 0 -lt $# ]; then echo optional; fi
source ./lib.sh
`, ""},
		{"standalone negation still follows a function's source command", `load() { source "$PLUGIN_ROOT/lib.sh"; }
! load
`, ""},
		{"standalone negation preserves the effects of a function call", `bind() { target="$PLUGIN_ROOT/lib.sh"; }
! bind
source "$target"
`, ""},
		{"file output and removal retain the numeric invariant", `count=0
tail -n "$limit" "$log" > "$backup"
for file in "$pending"/*.json; do
  [ -f "$file" ] && cat "$file" >> "$archive"
done
while IFS= read -r old; do [ -n "$old" ] && rm -f "$old"; done <<< "$old_files"
next=$((count + 1))
source "$PLUGIN_ROOT/lib.sh"
`, ""},
		{"file operations do not retain a dynamic source path", `target=./lib.sh
for file in "$pending"/*.json; do cat "$file" >> "$archive"; done
source "$target"
`, "hook_source_dynamic"},
		{"a shadowed file command may change shell values", `count=0
tail() { count="$runtime_value"; }
tail -n "$limit" "$log" > "$backup"
next=$((count + 1))
`, "hook_source_command_unverified"},
		{"arithmetic with typed file count", `if (( $(wc -c < "$file") > 200 )); then echo oversized; fi
source ./lib.sh
`, ""},
		{"arithmetic with raw file bytes", `if (( $(cat "$file") > 200 )); then echo oversized; fi
source ./lib.sh
`, "hook_source_command_unverified"},
		{"arithmetic conditional uses only known numeric inputs", "total=4\nstart=$((total > 3 ? total - 3 : 0))\n((start >= 0)) && source ./lib.sh\n", ""},
		{"arithmetic conditional does not validate an unknown input", "total=4\nstart=$((total > 3 ? total - 3 : unknown))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"cat with redirected here document preserves a source binding", `target=./lib.sh
cat >&2 <<EOF
message for $target
EOF
source "$target"
`, ""},
		{"JSON validation pipeline preserves a source binding", `target=./lib.sh
if ! printf '%s' "$input" | jq -e . >/dev/null 2>&1; then exit 0; fi
source "$target"
`, ""},
		{"cat function with here document can change a source binding", `target=./lib.sh
cat() { target="$request"; }
cat >&2 <<EOF
message for $target
EOF
source "$target"
`, "hook_source_command_unverified"},
		{"empty or decimal branch with arithmetic default", `value=$(cat runtime.txt)
if [ -n "$value" ] && ! [[ "$value" =~ ^[0123456789]+$ ]]; then value=; fi
result=$((${value:-0} + 1))
source ./lib.sh
`, ""},
		{"arithmetic default does not validate a value", "result=$((${value:-0} + 1))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"successful integer comparison validates both operands", `left=$(cat left.txt)
right=$(cat right.txt)
if [ "$left" -gt "$right" ]; then
  difference=$((left - right))
  printf '%s\n' "Difference $((difference + 1))"
fi
source ./lib.sh
`, ""},
		{"failed integer comparison does not validate an operand", `value=$(cat runtime.txt)
if [ "$value" -gt 0 ]; then :; else printf '%s\n' "Value $((value + 1))"; fi
source ./lib.sh
`, "hook_source_command_unverified"},
		{"unverified arithmetic even in a quoted argument", "printf '%s\\n' \"Count $((unknown + 1))\"\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"read loop with a Bash nonempty guard and regex", `target=./lib.sh
while IFS='=' read -r key value || [[ -n "${key}" ]]; do
  [[ "$key" =~ ^[[:space:]]*# ]] && continue
  printf '%s\n' "$value"
done < "$config"
source "$target"
`, ""},
		{"read loop discards an unused field", `target=./lib.sh
while IFS=: read -r item _; do printf '%s\n' "$item"; done <<< "$input"
source "$target"
`, ""},
		{"standalone increment preserves numeric type", `count=0
while IFS= read -r item; do ((count++)); done <<< "$input"
next=$((count + 1))
source ./lib.sh
`, ""},
		{"standalone increment requires a numeric value", "count=$(cat runtime.txt)\n((count++))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"finite quoted array can call a helper with runtime-only values", `consume() { source "$PLUGIN_ROOT/lib.sh"; }
dispatch() {
  local paths=("$HOME/.env" "$PWD/.env")
  for item in "${paths[@]}"; do
    consume "$item"
    if [ -n "$stop" ]; then return 0; fi
  done
}
dispatch
`, ""},
		{"group consuming a process substitution preserves unrelated bindings", `target=./lib.sh
{
  read -r event
  read -r subject
} < <(printf '%s\n' "$payload")
source "$target"
`, ""},
		{"group redirection with a nonstandard descriptor remains unverified", `{
  read -r event
} 7< <(printf '%s\n' "$payload")
source ./lib.sh
`, "hook_source_control_unverified"},
		{"bounded ref probe preserves unrelated bindings", `target=./lib.sh
for ref in origin/main main; do
  if git rev-parse --verify --quiet "$ref" >/dev/null 2>&1; then base="$ref"; break; fi
done
source "$target"
`, ""},
		{"array slice with a proven numeric offset", `items=(one two)
offset=1
for item in "${items[@]:$offset}"; do printf '%s\n' "$item"; done
source ./lib.sh
`, ""},
		{"array slice with unverified offset", `items=(one two)
for item in "${items[@]:$offset}"; do printf '%s\n' "$item"; done
source ./lib.sh
`, "hook_source_control_unverified"},
		{"known readonly source operand", "readonly target=./lib.sh\nsource \"$target\"\n", ""},
		{"readonly write cannot prove a new source operand", "readonly target=./lib.sh\ntarget=./other.sh\nsource \"$target\"\n", "hook_source_dynamic"},
		{"nested loop helper and status pipeline", `append() { notes+="$1"; }
record() {
  printf '%s\n' "$1" | grep -q 'ready' && append "$1"
}
while IFS= read -r line; do
  record "$line"
done
source ./lib.sh
`, ""},
		{"numeric branch values and loop counter", `if [ -t 0 ]; then count=0; else count=1; fi
while IFS= read -r line || [ -n "$line" ]; do
  count=$((count + 1))
done
[[ $count -gt 0 ]] && printf '%s\n' "$count"
source ./lib.sh
`, ""},
		{"digits from arbitrary file input", "count=$(cat \"$file\" | tr -cd 0123456789)\nnext=$((count + 1))\nsource ./lib.sh\n", ""},
		{"unfiltered file input", "count=$(cat \"$file\" || echo 0)\nnext=$((count + 1))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"jq array count with option delimiter", "count=$(jq '[.features[] | select(.done == false)] | length' -- \"$file\" 2>/dev/null || echo 0)\nnext=$((count + 1))\nsource ./lib.sh\n", ""},
		{"jq counts only arrays after filtering by type", "count=$(printf '%s\\n' \"$input\" | jq -e 'arrays | length') || exit 0\nnext=$((count + 1))\nsource ./lib.sh\n", ""},
		{"jq length also accepts numbers", "count=$(printf '%s\\n' \"$input\" | jq -e 'length') || exit 0\nnext=$((count + 1))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"jq file could change options", "count=$(jq '[.features[]] | length' \"$file\" 2>/dev/null || echo 0)\nnext=$((count + 1))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"jq default does not validate the value type", "count=$(jq -r '.count // 0' -- \"$file\")\nnext=$((count + 1))\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"a counter can be replaced by input", `count=0
while IFS= read -r line; do
  count="$line"
  count=$((count + 1))
done
source ./lib.sh
`, "hook_source_control_unverified"},
		{"fixed cleanup trap", "trap 'rm -f \"${note:-}\" 2>/dev/null || true' EXIT\nsource ./lib.sh\n", ""},
		{"cleanup trap redefined", "trap 'rm -f \"$note\"' EXIT\nrm() { source ./other.sh; }\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"bound scalar indirection", "key=TITLE\nmessage=\"hello ${!key:-fallback}\"\nsource ./lib.sh\n", ""},
		{"unbound scalar indirection", "key=\"$1\"\nmessage=\"hello ${!key:-fallback}\"\nsource ./lib.sh\n", "hook_source_command_unverified"},
		{"bound scalar indirection in test and arguments", `key=TITLE
if [[ -n "${!key:-}" ]]; then printf '%s' "${!key}"; fi
source ./lib.sh
`, ""},
		{"unbound scalar indirection in test", `key="$1"
if [[ -n "${!key:-}" ]]; then echo present; fi
source ./lib.sh
`, "hook_source_command_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, tc.script, "")
			if tc.gap == "" {
				assertHookTerminalPath(t, hooks, "p/lib.sh")
			} else if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == tc.gap }) {
				t.Fatalf("expected an unresolved shell effect: %+v", hooks)
			}
		})
	}
}

func TestUnquotedPluginRootDoesNotInheritGuardsAcrossLaunch(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "IFS=\nset -f\nbash \"$PLUGIN_ROOT/paths.sh\"\n",
		"bash $PLUGIN_ROOT/lib.sh\n")
	if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_unquoted_root" ||
		hooks.Diagnostics[0].Path != "p/paths.sh" {
		t.Fatalf("child shell inherited field splitting or globbing options: %+v", hooks)
	}
}

func TestUnquotedSourceCandidateDoesNotProveCallerBinding(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source $PLUGIN_ROOT/paths.sh\nsource \"$helper\"\n",
		"helper=\"$PLUGIN_ROOT/lib.sh\"\n")
	if len(hooks.Paths) != 2 || hooks.Paths[1].Target != "p/paths.sh" ||
		len(hooks.Diagnostics) != 2 || hooks.Diagnostics[0].Code != "hook_source_unquoted_root" ||
		hooks.Diagnostics[1].Code != "hook_source_command_unverified" {
		t.Fatalf("unverified source changed the caller's binding: %+v", hooks)
	}
}

func TestBashHookChecksExecutableTextWithoutShebang(t *testing.T) {
	const command = `"${CLAUDE_PLUGIN_ROOT}/start.sh"`
	_, _, hooks := inspectShellHook(t, command, "bash", "printf ready\n", true)
	assertHookTerminalPath(t, hooks, "p/start.sh")
	for _, tc := range []struct {
		mode, text string
		executable bool
	}{
		{"bash", "#!/bin/python\nprint('ready')\n", true},
		{"bash", "printf ready\n", false},
		{"sh", "printf ready\n", true},
	} {
		_, _, hooks := inspectShellHook(t, command, tc.mode, tc.text, tc.executable)
		if len(hooks.Paths) != 0 || len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_interpreter_unverified" {
			t.Fatalf("direct launch inferred without sufficient evidence: %+v", hooks)
		}
	}
}

func TestBashWrapperCaseTracesCaptureThroughExec(t *testing.T) {
	const handler = `: << 'BATCH'
@echo off
BATCH
case "$0" in
  */*|*\\*) dir="${0%[/\\]*}" ;;
  *) dir=wrong ;;
esac
script="$1"
shift
if [ -n "${BASH:-}" ]; then
  shell="$BASH"
else
  exit 0
fi
exec "$shell" "$dir/$script" "$@"
`
	_, _, hooks := inspectShellHook(t, `"${CLAUDE_PLUGIN_ROOT}/start.sh" helper`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")
	steps := hooks.Paths[len(hooks.Paths)-1].Steps
	if len(steps) != 2 || steps[0].Path != "p/hooks/hooks.json" || steps[1].Path != "p/start.sh" {
		t.Fatalf("missing wrapper launch evidence: %+v", steps)
	}
}

func TestHookFileGlobDispatchTracesCapturedFiles(t *testing.T) {
	const handler = `for file in "${CLAUDE_PLUGIN_ROOT}"/emitters/*; do
  [ -f "$file" ] && bash "$file" || true
done
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", handler, true,
		artifact.NewFile("p/emitters/first", []byte("[ \"${OPT_IN:-0}\" = 1 ] || exit 0\nprintf first\n"), true),
		artifact.NewFile("p/emitters/second.sh", []byte("if ls -1 items 2>/dev/null | grep -q .; then exit 0; fi\nprintf second\n"), true),
		artifact.NewFile("p/emitters/nested/ignored", []byte("printf ignored\n"), true),
	)
	targets := make([]string, 0, len(hooks.Paths))
	for _, p := range hooks.Paths {
		targets = append(targets, p.Target)
	}
	if len(hooks.Diagnostics) != 0 || !slices.Equal(targets, []string{"p/start.sh", "p/emitters/first", "p/emitters/second.sh"}) {
		t.Fatalf("unexpected glob paths or gaps: %+v", hooks)
	}
}

func inspectShellHook(t *testing.T, command, mode, handler string, executable bool, additional ...artifact.File) (report.ComponentGraph, []document.File, hooktrace.Sources) {
	t.Helper()

	return inspectShellHookWithOptions(t, report.HarnessOptions{}, command, mode, handler, executable, additional...)
}

func inspectShellHookWithOptions(t *testing.T, options report.HarnessOptions, command, mode, handler string, executable bool, additional ...artifact.File) (report.ComponentGraph, []document.File, hooktrace.Sources) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"SessionStart": []any{map[string]any{
		"hooks": []any{map[string]string{"type": "command", "command": command, "shell": mode}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	files := make([]artifact.File, 0, 4+len(additional))
	files = append(files,
		artifact.NewFile("p/.claude-plugin/plugin.json", []byte(`{"name":"example"}`), false),
		artifact.NewFile("p/hooks/hooks.json", data, false),
		artifact.NewFile("p/start.sh", []byte(handler), executable),
		artifact.NewFile("p/helper", []byte("printf helper\n"), false),
	)
	files = append(files, additional...)
	inventory := make([]report.File, 0, len(files))
	for _, file := range files {
		inventory = append(inventory, file.Metadata())
	}
	return harness.DiscoverWithHookSources(t.Context(), inventory, document.PrepareAll(t.Context(), files), report.ExtractionReport{}, options)
}

func TestHookReadOnlyScalarOperationsPreserveSourcePaths(t *testing.T) {
	const handler = `helper="${CLAUDE_PLUGIN_ROOT}/helper"
unset marker
slots=()
set +e
code=$?
if (( code < 5 && code != 2 )); then
  printf '%s\n' pending
fi
if [ "$(printf 1)" -gt "$limit" ] 2>/dev/null; then
  printf '%s\n' pending
fi
if ! git -C "$project" rev-parse --git-dir >/dev/null 2>&1; then
  exit 0
fi
source "$helper"
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")

	if len(hooks.Diagnostics) != 0 {
		t.Fatalf("unexpected source gaps: %+v", hooks.Diagnostics)
	}
}

func TestHookNumericBindingsRequireCheckedOperands(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		traced       bool
	}{
		{"enumerated digits", `if [[ ! "$value" =~ ^[0123456789]+$ ]]; then exit 0; fi`, true},
		{"C locale range", "LC_ALL=C\n" + `if [[ ! "$value" =~ ^[0-9]+$ ]]; then exit 0; fi`, true},
		{"range with unknown locale", `if [[ ! "$value" =~ ^[0-9]+$ ]]; then exit 0; fi`, false},
		{"count with option separator", `value=$(grep -c -- pattern "$file" 2>/dev/null || echo 0)`, true},
		{"count with unknown option boundary", `value=$(grep -c pattern "$file" 2>/dev/null || echo 0)`, false},
		{"count with known filename", `file=./log; value=$(grep -c pattern "$file" 2>/dev/null || echo 0)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const suffix = `
counter=$((value + 1))
if (( counter > 2 )); then
  printf '%s\n' pending
fi
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
			_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", tc.prefix+suffix, true)
			if tc.traced {
				assertHookTerminalPath(t, hooks, "p/helper")

				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("unexpected source gaps: %+v", hooks.Diagnostics)
				}
			} else if len(hooks.Diagnostics) == 0 || slices.ContainsFunc(hooks.Paths, func(p hooktrace.Path) bool {
				return p.Target == "p/helper"
			}) {
				t.Fatalf("unverified arithmetic was accepted: %+v", hooks)
			}
		})
	}
}

func TestHookArgumentConversionKeepsIndependentBindings(t *testing.T) {
	const handler = `helper="${CLAUDE_PLUGIN_ROOT}/helper"
converted=()
for arg in "$@"; do
  case "$arg" in
    /[A-Z]/*)
      if [ -n "$mode" ]; then
        drive="${arg:1:1}"
        rest="${arg:3}"
        converted+=("${drive^^}:${rest//\//\\}")
      else
        converted+=("$(printf '%s' "$arg")")
      fi
      ;;
    *) converted+=("$arg") ;;
  esac
done
set -- "${converted[@]}"
source "$helper"
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh" /c/path`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")

	if len(hooks.Diagnostics) != 0 {
		t.Fatalf("unexpected source gaps: %+v", hooks.Diagnostics)
	}
}

func TestHookSourceConsumesKnownPositionalArgumentsInShiftLoop(t *testing.T) {
	const handler = `while [[ $# -gt 0 ]]; do
  case "$1" in
    --init) helper="${CLAUDE_PLUGIN_ROOT}/helper"; shift ;;
    *) shift ;;
  esac
done
source "$helper"
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh" --other --init`, "bash", handler, false)
	assertHookTerminalPath(t, hooks, "p/helper")
}

func TestHookSourceConsumesOptionAndValueInShiftLoop(t *testing.T) {
	const handler = `while [ "$#" -gt 0 ]; do
  case "$1" in
    --file) helper="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
source "${CLAUDE_PLUGIN_ROOT}/$helper"
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh" --file helper --other`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")

	_, _, incomplete := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh" --file`, "bash", handler, true)
	if !slices.ContainsFunc(incomplete.Diagnostics, func(d report.Diagnostic) bool { return d.Code == "hook_source_control_unverified" }) {
		t.Fatalf("shift past the end of argv was accepted: %+v", incomplete)
	}
}

func TestHookSourceSummarizesDataOnlyShiftLoopWithUnknownArguments(t *testing.T) {
	const handler = `helper=./lib.sh
set -- @ARGV@
while [ $# -gt 0 ]; do
  case "$1" in
    on) @ARM@; shift; break ;;
    *) shift ;;
  esac
done
source "$helper"
`
	for _, tc := range []struct {
		name, args, arm, gap string
	}{
		{"preserves unrelated path", `$incoming`, `mode="$1"`, ""},
		{"preserves unrelated path with one runtime argument", `"$incoming"`, `mode="$1"`, ""},
		{"forgets a path assigned in one arm", `$incoming`, `helper=./other.sh`, "hook_source_dynamic"},
		{"does not skip a shell substitution", `$incoming`, `mode=$(source ./paths.sh)`, "hook_source_control_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, strings.NewReplacer("@ARM@", tc.arm, "@ARGV@", tc.args).Replace(handler), "")
			if tc.gap == "" {
				assertHookTerminalPath(t, hooks, "p/lib.sh")
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("data-only loop left gaps: %+v", hooks)
				}
			} else if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == tc.gap }) {
				t.Fatalf("unsafe loop or stale path had no gap: %+v", hooks)
			}
		})
	}
}

func TestHookProcessNamedOutputPreservesNumberFacts(t *testing.T) {
	const handler = `count=$(date -u +%s)
grep 'pattern' input > /tmp/scout-test.$$ 2>/dev/null
elapsed=$((count + 1))
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")
	if len(hooks.Diagnostics) != 0 {
		t.Fatalf("UTC epoch producer and redirected grep left gaps: %+v", hooks)
	}
}

func TestHookIntegerComparisonProofRequiresBash(t *testing.T) {
	const handler = `value=$(cat runtime.txt)
if [ "$value" -gt 0 ]; then
  checked=$((value + 1))
fi
source "${CLAUDE_PLUGIN_ROOT}/helper"
`
	_, _, hooks := inspectShellHook(t, `zsh "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "sh", handler, true)
	if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool { return d.Code == "hook_source_command_unverified" }) {
		t.Fatalf("Bash predicate proof was used for an unverified interpreter: %+v", hooks)
	}
}

func TestHookUnknownCaseSelectorTracesLiteralGlobArms(t *testing.T) {
	const handler = `case "${PLATFORM:-}" in
  [mM]sys*|cygwin*) source "${CLAUDE_PLUGIN_ROOT}/helper" ;;
esac
`
	_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", handler, true)
	assertHookTerminalPath(t, hooks, "p/helper")

	if len(hooks.Diagnostics) != 0 {
		t.Fatalf("unexpected source gaps: %+v", hooks.Diagnostics)
	}
}

func TestHookSourceTracesNestedInterpreterAndExec(t *testing.T) {
	const launch = `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`
	const handler = `bash "${CLAUDE_PLUGIN_ROOT}/relay"
`
	const relay = `exec /bin/bash "${CLAUDE_PLUGIN_ROOT}/helper"
`
	_, _, hooks := inspectShellHook(t, launch, "bash", handler, true, artifact.NewFile("p/relay", []byte(relay), false))
	assertHookTerminalPath(t, hooks, "p/helper")

	steps := hooks.Paths[len(hooks.Paths)-1].Steps
	if len(steps) != 3 || steps[1].Path != "p/start.sh" || steps[2].Path != "p/relay" {
		t.Fatalf("nested interpreter chain lost: %+v", steps)
	}
}

func TestHookSourcesReportUnresolvedIncludesAtTheirOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, command, script, code string
		paths                       int
	}{
		{"absent", `cd "$PLUGIN_ROOT" && bash ./install.sh`, "# line\nsource ./absent.sh\n", "hook_source_not_captured", 1},
		{"unknown directory", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource ./lib.sh\n", "hook_source_cwd_unknown", 1},
		{"unchecked cd", `cd "$PLUGIN_ROOT"; bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource ./lib.sh\n", "hook_source_cwd_unknown", 1},
		{"dynamic", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource \"$file\"\n", "hook_source_dynamic", 1},
		{"parent escape", `cd "$PLUGIN_ROOT" && bash ./install.sh`, "# line\nsource ../outside.sh\n", "hook_source_path_unverified", 1},
		{"cycle", `bash "$PLUGIN_ROOT/install.sh"`, "# line\n. \"$PLUGIN_ROOT/install.sh\"\n", "hook_source_cycle", 1},
		{"reassigned root", `bash "$PLUGIN_ROOT/install.sh"`, "PLUGIN_ROOT=/elsewhere\nsource \"$PLUGIN_ROOT/lib.sh\"\n", "hook_source_dynamic", 1},
		{"root changed by printf", `bash "$PLUGIN_ROOT/install.sh"`, "printf -v PLUGIN_ROOT %s /elsewhere\n. \"$PLUGIN_ROOT/lib.sh\"\n", "hook_source_dynamic", 1},
		{"directory operand", `cd "$PLUGIN_ROOT" && bash ./install.sh`, "# line\nsource ./lib.sh/\n", "hook_source_path_unverified", 1},
		{"directory dot operand", `cd "$PLUGIN_ROOT" && bash ./install.sh`, "# line\n. ./lib.sh/.\n", "hook_source_path_unverified", 1},
		{"source pipeline", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource \"$PLUGIN_ROOT/lib.sh\" | cat\n", "", 2},
		{"background file glob", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nfor f in \"$PLUGIN_ROOT\"/emitters/*; do [ -f \"$f\" ] && bash \"$f\" || true; done &\n", "", 1},
		{"shadowed file glob interpreter", `bash "$PLUGIN_ROOT/install.sh"`, "bash() { :; }\nfor f in \"$PLUGIN_ROOT\"/emitters/*; do [ -f \"$f\" ] && bash \"$f\" || true; done\n", "hook_source_control_unverified", 1},
		{"unknown arithmetic operand", `bash "$PLUGIN_ROOT/install.sh"`, "# line\n(( status < 5 ))\n", "hook_source_command_unverified", 1},
		{"unset command lookup", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nunset PATH\n", "hook_source_command_unverified", 1},
		{"unreachable include", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nfalse && source \"$PLUGIN_ROOT/lib.sh\"\n", "", 1},
		{"source redirection", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource \"$PLUGIN_ROOT/lib.sh\" >log\n", "hook_source_command_unverified", 1},
		{"unknown source option", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource -p ./lib.sh\n", "hook_source_command_unverified", 1},
		{"quoted data", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nprintf '%s' 'source ./absent.sh'\n", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := `{"name":"example"}`
			command, err := json.Marshal(tc.command)
			if err != nil {
				t.Fatal(err)
			}
			config := `{"SessionStart":[{"hooks":[{"type":"command","command":` + string(command) + `}]}]}`
			files := []artifact.File{
				artifact.NewFile("p/.codex-plugin/plugin.json", []byte(manifest), false),
				artifact.NewFile("p/hooks/hooks.json", []byte(config), false),
				artifact.NewFile("p/install.sh", []byte(tc.script), false),
				artifact.NewFile("p/lib.sh", []byte("printf ready\n"), false),
				artifact.NewFile("outside.sh", []byte("printf outside\n"), false),
			}
			inventory := make([]report.File, 0, len(files))
			for _, file := range files {
				inventory = append(inventory, file.Metadata())
			}
			_, _, hooks := harness.DiscoverWithHookSources(t.Context(), inventory, document.PrepareAll(t.Context(), files), report.ExtractionReport{}, report.HarnessOptions{})
			if len(hooks.Paths) != tc.paths || hooks.Paths[0].Target != "p/install.sh" || hooks.Paths[0].Event != "SessionStart" {
				t.Fatalf("unexpected source paths: %+v", hooks.Paths)
			}
			if tc.code == "" {
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("unexpected gaps: %+v", hooks.Diagnostics)
				}
				return
			}
			if len(hooks.Diagnostics) != 1 {
				t.Fatalf("expected one source gap: %+v", hooks.Diagnostics)
			}
			if d := hooks.Diagnostics[0]; d.Code != tc.code || d.Path != "p/install.sh" || d.Line != 2 || d.Column != 1 || !d.AffectsScope {
				t.Fatalf("incorrect source gap: %+v", d)
			}
		})
	}
}

func TestHookArgvFileLaunchWithOptions(t *testing.T) {
	const config = `{"SessionStart":[{"hooks":[{"type":"command","command":"bash","args":["-eu","-o","pipefail","--","${PLUGIN_ROOT}/start.sh"]}]}]}`
	files := []artifact.File{
		artifact.NewFile("p/.codex-plugin/plugin.json", []byte(`{"name":"example"}`), false),
		artifact.NewFile("p/hooks/hooks.json", []byte(config), false),
		artifact.NewFile("p/start.sh", []byte("printf ready\n"), false),
	}
	inventory := make([]report.File, 0, len(files))
	for _, file := range files {
		inventory = append(inventory, file.Metadata())
	}

	_, _, hooks := harness.DiscoverWithHookSources(t.Context(), inventory, document.PrepareAll(t.Context(), files), report.ExtractionReport{}, report.HarnessOptions{})
	if len(hooks.Paths) != 1 || hooks.Paths[0].Target != "p/start.sh" || len(hooks.Diagnostics) != 0 {
		t.Fatalf("unexpected shell argv result: %+v", hooks)
	}
}

func TestHookSourcePathSubstitutions(t *testing.T) {
	const launch = `/bin/bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`
	for _, tc := range []struct {
		name, script, gap string
	}{
		{"script argument", `source "$(dirname "$0")/helper"`, ""},
		{"Bash source", `source "$(dirname "${BASH_SOURCE[0]}")/helper"`, ""},
		{"checked directory with discarded output", `base="$(cd "$(dirname "$0")/sub/.." && pwd)"
bash "$base/helper" 2>/dev/null`, ""},
		{"file launch with fixed shell options", `bash -eu -o pipefail -- "${CLAUDE_PLUGIN_ROOT}/helper"`, ""},
		{"missing intermediate directory", `base="$(cd "$(dirname "$0")/missing/.." && pwd)"
source "$base/helper"`, "hook_source_dynamic"},
		{"shadowed dirname", `dirname() { printf ignored; }
source "$(dirname "$0")/helper"`, "hook_source_dynamic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, hooks := inspectShellHook(t, launch, "bash", tc.script, true,
				artifact.NewFile("p/sub/note.txt", []byte("captured"), false))
			if tc.gap == "" {
				assertHookTerminalPath(t, hooks, "p/helper")
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("unexpected gaps: %+v", hooks.Diagnostics)
				}

				return
			}

			if slices.ContainsFunc(hooks.Paths, func(p hooktrace.Path) bool { return p.Target == "p/helper" }) ||
				len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != tc.gap {
				t.Fatalf("expected unresolved source, got %+v", hooks)
			}
		})
	}
}

func TestHookSourceFlow(t *testing.T) {
	for _, tc := range []struct {
		name, install, pathsScript, want, code string
		line                                   int
		column                                 int
	}{
		{name: "constant from source", install: ". \"$PLUGIN_ROOT/paths.sh\"\nsource \"$helper\"\n", pathsScript: "base=\"$PLUGIN_ROOT\"\nexport helper=\"$base/lib.sh\"\n", want: "p/lib.sh"},
		{name: "case selects first matching arm", install: "case value in other|value) helper=./lib.sh ;; *) helper=./other.sh ;; esac\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "case with no match preserves state", install: "helper=./lib.sh\ncase value in other) helper=./other.sh ;; esac\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "while assignment preserves independent bindings", install: "helper=./lib.sh\nwhile [[ $text == *$'\\n' ]]; do text=\"${text%$'\\n'}\"; done\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "while assignment invalidates old binding", install: "helper=./lib.sh\nwhile [[ -n \"$text\" ]]; do helper=./other.sh; done\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "while command body stays unverified", install: "while [[ -n \"$text\" ]]; do source ./lib.sh; done\n", code: "hook_source_control_unverified", line: 1},
		{name: "while lookup option stays unverified", install: "while [[ -n \"$text\" ]]; do PATH=/other; done\n", code: "hook_source_control_unverified", line: 1},
		{name: "directory retry resolves a guarded clock calculation", install: "until mkdir -- \"$lock\" 2>/dev/null; do\n mtime=$payload\n if [[ \"$mtime\" =~ ^[0123456789]+$ ]]; then\n  now=$(date +%s)\n  if (( now - mtime > 6 )); then rmdir -- \"$lock\" 2>/dev/null; fi\n fi\n sleep 0.05\ndone\nsource \"$PLUGIN_ROOT/lib.sh\"\n", want: "p/lib.sh"},
		{name: "shadowed directory creation stays unverified in a retry", install: "mkdir() { :; }\nuntil mkdir -- \"$lock\" 2>/dev/null; do sleep 0.05; done\n", code: "hook_source_control_unverified", line: 2},
		{name: "fresh temporary file preserves redirected function tracing", install: "helper=./lib.sh\nhandler() { source \"$helper\"; }\ntmp=$(mktemp) || exit 0\nhandler >\"$tmp\" 2>/dev/null\n", want: "p/lib.sh"},
		{name: "unverified temporary helper leaves a redirected function gap", install: "mktemp() { printf fixed; }\nhandler() { source ./lib.sh; }\ntmp=$(mktemp) || exit 0\nhandler >\"$tmp\" 2>/dev/null\n", code: "hook_source_command_unverified", line: 4},
		{name: "directory cleanup trap is tracked until exit", install: "trap 'rmdir -- \"$lock\" 2>/dev/null' EXIT\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "cleanup trap requires an option boundary for multiple paths", install: "trap 'rm -f \"$first\" \"$second\"' EXIT\n", code: "hook_source_command_unverified", line: 1},
		{name: "cleanup trap with multiple scalar paths", install: "trap 'rm -f -- \"$first\" \"$second\" 2>/dev/null' EXIT\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "cleanup trap with quoted paths from an array", install: "trap 'rm -f -- \"${paths[@]:-}\" 2>/dev/null || true' EXIT\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "cleanup trap keeps an array option boundary", install: "trap 'rm -f \"${paths[@]:-}\" 2>/dev/null || true' EXIT\n", code: "hook_source_command_unverified", line: 1},
		{name: "exit trap calls a cleanup function with an array loop", install: "cleanup() { for item in \"${paths[@]:-}\"; do rm -f \"$item\" 2>/dev/null || true; done; }\ntrap cleanup EXIT\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "exit trap rejects a function with other commands", install: "cleanup() { for item in \"${paths[@]:-}\"; do source \"$item\"; done; }\ntrap cleanup EXIT\n", code: "hook_source_command_unverified", line: 2},
		{name: "exit trap catches a later definition on either branch", install: "cleanup() { rm -f -- \"$item\"; }\nif [ -f ./paths.sh ]; then trap cleanup EXIT; fi\ncleanup() { :; }\n", code: "hook_source_command_unverified", line: 3},
		{name: "exit trap catches a shadowed command in the cleanup function", install: "cleanup() { rm -f -- \"$item\"; }\ntrap cleanup EXIT\nrm() { :; }\n", code: "hook_source_command_unverified", line: 3},
		{name: "read loop preserves unrelated binding", install: "helper=./lib.sh\ncount=$(printf '%s\\n' \"$lines\" | wc -l)\nwhile IFS= read -r line; do [[ -z \"$line\" ]] && continue; if [[ $count -gt 1 ]]; then result=\"$line\"; fi; done <<<\"$lines\"\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "read array inside a loop preserves unrelated bindings", install: "helper=./lib.sh\nwhile IFS= read -r row; do read -ra words <<< \"$row\"; for word in \"${words[@]}\"; do seen=\"$word\"; done; done <<< \"$rows\"\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "read inside a loop invalidates the destination", install: "helper=./lib.sh\nwhile IFS= read -r row; do read -r helper <<< \"$row\"; done <<< \"$rows\"\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "read loop cannot reuse a numeric binding written by the body", install: "count=2\nwhile IFS= read -r line; do if [[ $count -gt 1 ]]; then count=\"$line\"; fi; done <<<\"$lines\"\n", code: "hook_source_control_unverified", line: 2},
		{name: "read loop does not trust shadowed line counter", install: "wc() { echo text; }\ncount=$(printf '%s\\n' \"$lines\" | wc -l)\nwhile IFS= read -r line; do if [[ $count -gt 1 ]]; then result=\"$line\"; fi; done <<<\"$lines\"\n", code: "hook_source_control_unverified", line: 3},
		{name: "read loop traverses sources in substitutions", install: "while IFS= read -r line; do result=$(source ./lib.sh); done <<<\"$lines\"\n", want: "p/lib.sh"},
		{name: "quoted array loop preserves unrelated bindings", install: "helper=./lib.sh\nfor word in \"${items[@]}\"; do if [[ $word == done ]]; then break; fi; found=\"$word\"; done\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "loop drops values possibly written", install: "helper=./lib.sh\nfor word in one two; do helper=./other.sh; done\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "multi-field heredoc read preserves independent binding", install: "helper=./lib.sh\nwhile IFS='|' read -r key val; do seen=\"$key\"; done <<EOF\n$rows\nEOF\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "read loop accepts a separator from constant printf", install: "helper=./lib.sh\nwhile IFS=\"$(printf '\\t')\" read -r key val; do seen=\"$key\"; done <<<\"$rows\"\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "read loop rejects a shadowed separator command", install: "printf() { echo tab; }\nwhile IFS=\"$(printf '\\t')\" read -r key val; do seen=\"$key\"; done <<<\"$rows\"\n", code: "hook_source_control_unverified", line: 2},
		{name: "read-only pipeline preserves source path", install: "helper=./lib.sh\nprintf '%s' \"$text\" | grep -q data | wc -l\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "printf format writing variables invalidates pipeline state", install: "helper=./lib.sh\necho yes | printf '%n' helper\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "Bash test traces child source", install: "if [[ -n \"$(source ./lib.sh)\" ]]; then :; fi\n", want: "p/lib.sh"},
		{name: "for word default traces child source", install: "for name in \"${data:-$(source ./lib.sh)}\"; do :; done\n", want: "p/lib.sh"},
		{name: "default word traces child source", install: "value=\"${data:-$(source ./lib.sh)}\"\n", want: "p/lib.sh"},
		{name: "process substitution traces child source", install: "cat < <(source ./lib.sh)\n", want: "p/lib.sh"},
		{name: "count with redirected input and whitespace removal", install: "count=$(wc -c < \"$log\" 2>/dev/null | tr -d ' ' || echo 0)\ncopy=$((count + 1))\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "numeric command fallback must also be proved", install: "count=$(date +%s || printf '%s' \"$payload\")\ncopy=$((count + 1))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "anchored signed decimal with numeric fallback", install: "epoch=$payload\nif [[ ! \"$epoch\" =~ ^-?[0123456789]+$ ]]; then epoch=0; fi\ncopy=$((epoch + 1))\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "unanchored decimal does not establish numeric provenance", install: "epoch=$payload\nif [[ ! \"$epoch\" =~ [0123456789]+$ ]]; then epoch=0; fi\ncopy=$((epoch + 1))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 3},
		{name: "numeric helper and scalar copy preserve proof", install: "int_or() { if [[ ${1:-} =~ ^[0123456789]+$ ]]; then printf '%s' \"$1\"; else printf '%s' \"$2\"; fi; }\ncount=$(int_or \"$payload\" 0)\ncopy=$count\nnext=$((copy + 1))\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "numeric helper rejects an unknown fallback", install: "int_or() { if [[ ${1:-} =~ ^[0123456789]+$ ]]; then printf '%s' \"$1\"; else printf '%s' \"$2\"; fi; }\ncount=$(int_or \"$payload\" \"$unknown\")\nnext=$((count + 1))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 3},
		{name: "numeric helper requires proof of locale for a digit range", install: "int_or() { if [[ ${1:-} =~ ^[0-9]+$ ]]; then printf '%s' \"$1\"; else printf '%s' \"$2\"; fi; }\ncount=$(int_or \"$payload\" 0)\nnext=$((count + 1))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 3},
		{name: "local initialization preserves proved arithmetic result", install: "run() { count=$(date +%s); local first=$((count + 1)) unused; next=$((first + 1)); source ./lib.sh; }\nrun\n", want: "p/lib.sh"},
		{name: "local initialization rejects unknown arithmetic input", install: "run() { local first=$((payload + 1)) unused; source ./lib.sh; }\nrun\n", code: "hook_source_command_unverified", line: 1, column: 9},
		{name: "shadowed date has no numeric summary", install: "date() { printf '%s' \"$payload\"; }\ncount=$(date +%s)\ncopy=$((count + 1))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 3},
		{name: "literal positional option dispatch", install: "prepare() { for arg in \"$@\"; do case \"$arg\" in --file=*) helper=\"${arg#--file=}\" ;; *) missing=./other.sh ;; esac; done; }\nprepare --file=./lib.sh\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "known empty positional list skips loop body", install: "for item in \"$@\"; do source ./missing.sh; done\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "arithmetic clock field uses decimal base", install: "hour=$((10#$(date +%H)))\ncount=$((hour + 1))\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "arithmetic clock field rejects shadowed command", install: "date() { printf '%s' \"$payload\"; }\nhour=$((10#$(date +%H)))\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "nested index through a decimal array", install: "codes=(one two)\nindexes=(0 1)\nhour=$((10#$(date +%H)))\nresult=${codes[indexes[hour]]}\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "literal array index", install: "codes=(one two)\nresult=${codes[0]}\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "literal subscript does not evaluate an unknown index", install: "result=${codes[0]}\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "local array bindings are scoped to the function", install: "codes=./lib.sh\nprepare() { local codes=(one two); index=1; result=${codes[index]}; }\nprepare\nsource \"$codes\"\n", want: "p/lib.sh"},
		{name: "literal ANSI-C read delimiter preserves an independent path", install: "helper=./lib.sh\nIFS=$'\\x1f' read -r field < <(printf '%s' record)\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "literal ANSI-C separator assignment preserves command lookup", install: "IFS=$'\\n\\t'\ncommand -v jq >/dev/null 2>&1 || exit 0\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "unquoted array length in decimal comparison", install: "tokens=(one two)\nif [ ${#tokens[@]} -gt 0 ]; then source ./lib.sh; fi\n", want: "p/lib.sh"},
		{name: "unquoted scalar length in decimal comparison", install: "if [ ${#text} -gt 0 ]; then source ./lib.sh; fi\n", want: "p/lib.sh"},
		{name: "a read loop may declare a local", install: "prepare() { while IFS= read -r line; do local row; row=\"$line\"; done; source ./lib.sh; }\nprepare\n", want: "p/lib.sh"},
		{name: "a loop may shadow a later assignment", install: "helper=./other.sh\nprepare() { while IFS= read -r line; do local helper; done; helper=./lib.sh; }\nprepare\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 4},
		{name: "noglob toggle preserves independent source operand", install: "file=./lib.sh\nset -f\nset +f\nsource \"$file\"\n", want: "p/lib.sh"},
		{name: "array index with an unknown numeric value", install: "codes=(one two)\nresult=${codes[index]}\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "reassignment loses proof of decimal array contents", install: "codes=(one two)\nindexes=(0 1)\nindexes=(\"$payload\")\nresult=${codes[indexes[0]]}\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 4},
		{name: "append loses proof of decimal array contents", install: "codes=(one two)\nindexes=(0 1)\nindexes+=(\"$payload\")\nresult=${codes[indexes[0]]}\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 4},
		{name: "numerical array fact must hold on both branches", install: "codes=(one two)\nif [ -f ./paths.sh ]; then indexes=(0 1); else indexes=(\"$payload\"); fi\nresult=${codes[indexes[0]]}\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 3},
		{name: "complex array index stays outside the projection", install: "codes=(one two)\nresult=${codes[index+=1]}\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "array length test preserves bindings", install: "helper=./lib.sh\nif [ \"${#items[@]}\" -gt 0 ]; then :; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "temporary scalar environment passes into file launch", install: "SESSION=$id bash ./lib.sh 2>/dev/null\n", want: "p/lib.sh"},
		{name: "temporary PATH is still unresolved", install: "PATH=/custom/bin bash ./lib.sh 2>/dev/null\n", code: "hook_source_command_unverified", line: 1},
		{name: "substitution does not leak assignments", install: "helper=./lib.sh\nresult=$(helper=./other.sh)\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "unknown numeric predicate stays unverified", install: "if [[ $unknown -gt 1 ]]; then :; fi\n", code: "hook_source_command_unverified", line: 1, column: 4},
		{name: "negated predicate retains continuation through redirected echo", install: "helper=./lib.sh\nif ! [[ $mode =~ ^ready$ ]]; then echo skipped >&2; exit 0; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "quoted case star is literal", install: "case value in '*') helper=./other.sh ;; *) helper=./lib.sh ;; esac\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "case with unknown selector traces possible source", install: "case \"$unknown\" in *) source ./lib.sh ;; esac\n", want: "p/lib.sh"},
		{name: "case with unmodeled glob traces possible arms", install: "case value in v*) source ./lib.sh ;; esac\n", want: "p/lib.sh"},
		{name: "case default removes unmatched path", install: "case \"$input\" in yes) helper=./lib.sh ;; *) helper=./lib.sh ;; esac\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "quoted case star still permits no match", install: "case \"$input\" in '*') helper=./lib.sh ;; esac\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "case fallthrough stays unverified", install: "case value in value) helper=./lib.sh ;& *) helper=./other.sh ;; esac\nsource \"$helper\"\n", code: "hook_source_control_unverified", line: 1},
		{name: "unary file test preserves bindings on both paths", install: "helper=./lib.sh\nif [ -r \"$file\" ]; then :; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "eval of literal printf preserves source bindings", install: "note='printf \"%s\\n\" ready'\neval \"$note\"\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "eval with unknown effects stops tracing", install: "eval \"$note\"\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 1},
		{name: "ignore pipe in function preserves relative source bindings", install: "helper=./lib.sh\nprepare() { trap '' PIPE; }\nprepare\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "ignore SIGPIPE preserves relative source bindings", install: "helper=./lib.sh\ntrap '' SIGPIPE\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "trap function is analyzed as a function", install: "helper=./other.sh\ntrap() { helper=./lib.sh; }\ntrap '' PIPE\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "exit trap preserves source on continuing path", install: "helper=./lib.sh\ntrap 'echo stopped >&2; exit 0' ERR\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "redefinition after conditional trap stays unverified", install: "if [ -f ./paths.sh ]; then trap 'exit 0' ERR; fi\nexit() { :; }\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "trap with shell handler stays unverified", install: "trap 'helper=./other.sh' PIPE\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 1},
		{name: "trap with dynamic action stays unverified", install: "action=\ntrap \"$action\" PIPE\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "trap with extra signal stays unverified", install: "trap '' PIPE EXIT\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 1},
		{name: "trap with redirect stays unverified", install: "trap '' PIPE >out\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 1},
		{name: "command lookup preserves bindings on continuing branch", install: "if ! command -v tool &>/dev/null; then exit 0; fi\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "guarded assignment and exit group", install: "helper=\"$(printf ./lib.sh)\" || { printf failed; exit 1; }\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "read-only Bash test preserves bindings", install: "[[ -z \"$mode\" ]] && exit 0\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "arithmetic Bash test stays unverified", install: "[[ $((helper=1)) -eq 1 ]] && exit 0\nsource ./lib.sh\n", code: "hook_source_control_unverified", line: 1},
		{name: "nested constants", install: ". \"$PLUGIN_ROOT/paths.sh\"\nsource \"$helper\"\n", pathsScript: "source \"$PLUGIN_ROOT/base.sh\"\nhelper=\"$base/lib.sh\"\n", want: "p/lib.sh"},
		{name: "unknown reassignment", install: ". \"$PLUGIN_ROOT/paths.sh\"\nhelper=\"$unresolved\"\nsource \"$helper\"\n", pathsScript: "helper=\"$PLUGIN_ROOT/lib.sh\"\n", code: "hook_source_dynamic", line: 3},
		{name: "same path", install: "if test a = b; then helper=./lib.sh; else helper=./lib.sh; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "different paths", install: "if test a = b; then helper=./lib.sh; else helper=./other.sh; fi\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "implicit else", install: "if test a = b; then helper=./lib.sh; fi\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "same paths after nested branches", install: "if test a = b; then helper=./lib.sh; elif test a = c; then helper=./lib.sh; else helper=./lib.sh; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "negated file tests preserve source", install: "helper=./lib.sh\nif [ ! -L \"$file\" ] && [ ! -s \"$file\" ] 2>/dev/null; then :; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "test with indirect expansion remains unverified", install: "helper=./lib.sh\n[ -v \"$user\" ]\nsource \"$helper\"\n", code: "hook_source_command_unverified", line: 2},
		{name: "project root default short circuits its fallback", install: "base=\"${PLUGIN_ROOT:-$(source ./missing.sh)}\"\nsource \"$base/lib.sh\"\n", want: "p/lib.sh"},
		{name: "quoted project root default with path suffix", install: "source \"${PLUGIN_ROOT:-$(source ./missing.sh)}/lib.sh\"\n", want: "p/lib.sh"},
		{name: "project root default keeps active sibling substitution", install: "echo \"${PLUGIN_ROOT:-$(source ./missing.sh)}/$(source ./lib.sh)\"\n", want: "p/lib.sh"},
		{name: "printf can change the plugin root binding", install: "printf -- '%n' PLUGIN_ROOT\nbase=\"${PLUGIN_ROOT:-fallback}\"\nsource \"$base/lib.sh\"\n", code: "hook_source_dynamic", line: 3},
		{name: "captured exec target is traced", install: "base=\"${PLUGIN_ROOT:-fallback}\"\nexec \"$base/lib.sh\"\n", code: "hook_source_interpreter_unverified", line: 2},
		{name: "background subshell with discarded output has local bindings", install: "helper=./lib.sh\n(helper=./other.sh) >/dev/null 2>&1 &\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "background and list shares one isolated shell", install: "helper=./other.sh\nhelper=./lib.sh && source \"$helper\" &\n", want: "p/lib.sh"},
		{name: "pipeline last stage can modify a binding", install: "helper=./other.sh\necho ok | helper=./lib.sh\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "pipeline read preserves independent source", install: "helper=./lib.sh\necho ok | IFS= read -r result\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "pipeline read forgets possible written destination", install: "helper=./lib.sh\necho ok | IFS= read -r helper\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 3},
		{name: "redirected brace group traces a source", install: "{ source ./lib.sh; } 2>/dev/null\n", want: "p/lib.sh"},
		{name: "append-only lock guard traces the success path", install: "(flock -n 200 || exit 0; source \"$PLUGIN_ROOT/lib.sh\") 200>>\"$lock\"\n", want: "p/lib.sh"},
		{name: "lock guard with a different descriptor stays unverified", install: "(flock -n 201 || exit 0; source \"$PLUGIN_ROOT/lib.sh\") 200>>\"$lock\"\n", code: "hook_source_control_unverified", line: 1},
		{name: "truncating lock redirection stays unverified", install: "(flock -n 200 || exit 0; source \"$PLUGIN_ROOT/lib.sh\") 200>\"$lock\"\n", code: "hook_source_control_unverified", line: 1},
		{name: "conditional loop forgets only loop bindings", install: "helper=./lib.sh\nwhile [[ $dir != / ]]; do if [ -f \"$dir/test\" ]; then break; fi; dir=$(dirname \"$dir\"); done\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "literal system PATH and bare export preserve shell bindings", install: "helper=./lib.sh\nPATH=/usr/bin:/bin\nexport PATH\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "custom PATH still invalidates lookup", install: "helper=./lib.sh\nPATH=/custom/bin:/bin\nsource \"$helper\"\n", code: "hook_source_command_unverified", line: 3},
		{name: "same directory", install: "if test a = b; then cd ./sub || exit; else cd \"$PLUGIN_ROOT/sub\" || exit; fi\nsource ./lib.sh\n", want: "p/sub/lib.sh"},
		{name: "different directories", install: "if test a = b; then cd ./sub || exit; else cd . || exit; fi\nsource ./lib.sh\n", code: "hook_source_cwd_unknown", line: 2},
		{name: "independent rooted path after different directories", install: "if test a = b; then cd ./sub || exit; else cd . || exit; fi\nsource \"$PLUGIN_ROOT/lib.sh\"\n", want: "p/lib.sh"},
		{name: "working directory across source", install: "source ./paths.sh\nsource ./lib.sh\n", pathsScript: "cd ./sub || exit\n", want: "p/sub/lib.sh"},
		{name: "conditional assignment does not escape and list", install: "test a = b && helper=./lib.sh\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "conditional source does not leak cwd", install: "cd ./sub && source \"$PLUGIN_ROOT/paths.sh\"\nsource ./lib.sh\n", pathsScript: "true\n", code: "hook_source_cwd_unknown", line: 2},
		{name: "known skipped and list", install: "helper=./lib.sh\nfalse && helper=./other.sh\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "literal true selects branch", install: "if true; then helper=./lib.sh; else helper=./other.sh; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "function return stops body", install: "source ./paths.sh\nprepare\nsource \"$helper\"\n", pathsScript: "prepare() { helper=./lib.sh; return; helper=./other.sh; }\n", want: "p/lib.sh"},
		{name: "source arguments", install: "source ./paths.sh ./lib.sh\nsource \"$helper\"\n", pathsScript: "helper=\"$1\"\n", want: "p/lib.sh"},
		{name: "function arguments", install: "source ./paths.sh\nprepare ./lib.sh\nsource \"$helper\"\n", pathsScript: "prepare() { helper=\"$1\"; }\n", want: "p/lib.sh"},
		{name: "nested function sees local argument", install: "helper=./other.sh\nload() { source \"$helper\"; }\nprepare() { local helper=\"$1\"; load; }\nprepare ./lib.sh\n", want: "p/lib.sh"},
		{name: "return restores shadowed value and preserves global writes", install: "helper=./other.sh\nprepare() { helper=./lib.sh; local helper=./other.sh; result=\"$helper\"; return; }\nprepare\nif [ -n \"$result\" ]; then source \"$helper\"; fi\n", want: "p/lib.sh"},
		{name: "local initializers expand before declaration", install: "helper=./lib.sh\nprepare() { local helper=./other.sh saved=\"$helper\"; source \"$saved\"; }\nprepare\n", want: "p/lib.sh"},
		{name: "nested local restores caller local", install: "helper=./other.sh\ninner() { local helper=\"$unknown\"; }\nouter() { local helper=./lib.sh; inner; source \"$helper\"; }\nouter\n", want: "p/lib.sh"},
		{name: "local in sourced file shares function scope", install: "helper=./lib.sh\nprepare() { source ./paths.sh; }\nprepare\nsource \"$helper\"\n", pathsScript: "local helper=./other.sh\n", want: "p/lib.sh"},
		{name: "bare local hides caller value", install: "helper=./lib.sh\nprepare() {\n  local helper\n  source \"$helper\"\n}\nprepare\n", code: "hook_source_dynamic", line: 4, column: 3},
		{name: "conditional local can leave outer value changed", install: "helper=./lib.sh\nprepare() {\n  if [ -f ./paths.sh ]; then local helper; fi\n  helper=./other.sh\n}\nprepare\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 7},
		{name: "both branches restore the same outer binding", install: "helper=./lib.sh\nprepare() { if [ -f ./paths.sh ]; then local helper=./other.sh; return; else local helper; fi; }\nprepare\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "local outside function remains unverified", install: "local helper=./lib.sh\nsource \"$helper\"\n", code: "hook_source_command_unverified", line: 1},
		{name: "local attributes remain unverified", install: "prepare() {\n  local -n helper=target\n}\nprepare\n", code: "hook_source_command_unverified", line: 2, column: 3},
		{name: "local assignment variants remain unverified", install: "prepare() {\n  local helper+=./lib.sh\n}\nprepare\n", code: "hook_source_command_unverified", line: 2, column: 3},
		{name: "local word operands remain unverified", install: "prepare() {\n  local \"helper=$@\"\n}\nprepare ./lib.sh other\n", code: "hook_source_command_unverified", line: 2, column: 3},
		{name: "function arguments stop after dynamic expansion", install: "source ./paths.sh\nprepare $unknown ./lib.sh\nsource \"$helper\"\n", pathsScript: "prepare() { helper=\"$2\"; }\n", code: "hook_source_dynamic", line: 3},
		{name: "function with stderr discarded retains a path for its body", install: "prepare() { source ./lib.sh; }\nprepare 2>/dev/null\n", want: "p/lib.sh"},
		{name: "function with redirected file input retains a path for its body", install: "prepare() { source ./lib.sh; }\nprepare < \"$input\" 2>/dev/null\n", want: "p/lib.sh"},
		{name: "input redirection can fail before a function mutates its caller", install: "helper=./other.sh\nprepare() { helper=./lib.sh; }\nprepare < \"$input\"\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 4},
		{name: "quoted join of array values does not change bindings", install: "helper=./lib.sh\necho \"Items: ${items[*]}\" >&2\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "redirection failure can leave the caller binding unchanged", install: "helper=./other.sh\nprepare() { helper=./lib.sh; }\nprepare 2>/dev/null\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 4},
		{name: "same function survives branches", install: "source ./paths.sh\nif test a = b; then true; else false; fi\nprepare\n", pathsScript: "prepare() { source ./lib.sh; }\n", want: "p/lib.sh"},
		{name: "source return stops body", install: "source ./paths.sh\nsource \"$helper\"\n", pathsScript: "helper=./lib.sh\nreturn\nhelper=./other.sh\n", want: "p/lib.sh"},
		{name: "early source return preserves independent binding", install: "source ./paths.sh\nsource \"$helper\"\n", pathsScript: "helper=./lib.sh\nif test a = b; then return; fi\nunused=./other.sh\n", want: "p/lib.sh"},
		{name: "early and normal source returns agree", install: "source ./paths.sh\nsource \"$helper\"\n", pathsScript: "if test a = b; then helper=./lib.sh; return; fi\nhelper=./lib.sh\n", want: "p/lib.sh"},
		{name: "early and normal source returns disagree", install: "source ./paths.sh\nsource \"$helper\"\n", pathsScript: "if test a = b; then helper=./other.sh; return; fi\nhelper=./lib.sh\n", code: "hook_source_dynamic", line: 2},
		{name: "returned branch does not pollute the continuing branch", install: "source ./paths.sh\n", pathsScript: "helper=./lib.sh\nif test a = b; then helper=./other.sh; return; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "exited branch does not pollute the continuing branch", install: "helper=./lib.sh\nif test a = b; then helper=./other.sh; exit; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "true and list preserves assignment", install: "true && helper=./lib.sh\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "directory test", install: "if cd ./sub; then source ./lib.sh; fi\n", want: "p/sub/lib.sh"},
		{name: "failed directory test keeps original directory", install: "if cd ./sub; then exit; else source ./lib.sh; fi\n", want: "p/lib.sh"},
		{name: "directory test with terminating fallback", install: "if cd ./sub; then true; else exit; fi\nsource ./lib.sh\n", want: "p/sub/lib.sh"},
		{name: "negated directory change leaves a relative source unresolved", install: "! cd ./sub\nsource ./lib.sh\n", code: "hook_source_cwd_unknown", line: 2},
		{name: "piped directory change is isolated", install: "cd ./sub | cat\nsource ./lib.sh\n", want: "p/lib.sh"},
		{name: "guarded directory change invalidates stale PWD", install: "PWD=\"$PLUGIN_ROOT\"\ncd ./sub || exit\nsource \"$PWD/lib.sh\"\n", code: "hook_source_dynamic", line: 3},
		{name: "directory test invalidates stale OLDPWD", install: "OLDPWD=\"$PLUGIN_ROOT/sub\"\nif cd ./sub; then\nsource \"$OLDPWD/lib.sh\"\nfi\n", code: "hook_source_dynamic", line: 3},
		{name: "ambiguous function after join", install: "if test a = b; then source ./paths.sh; fi\nprepare\n", pathsScript: "prepare() { source ./lib.sh; }\n", code: "hook_source_function_unverified", line: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, tc.install, tc.pathsScript)
			got := ""
			for _, p := range hooks.Paths {
				switch p.Target {
				case "p/lib.sh", "p/other.sh", "p/sub/lib.sh":
					if got != "" {
						t.Fatalf("multiple terminal paths: %+v", hooks.Paths)
					}
					got = p.Target
				}
			}
			if got != tc.want {
				t.Fatalf("terminal path = %q, want %q, paths = %+v, gaps = %+v", got, tc.want, hooks.Paths, hooks.Diagnostics)
			}
			if tc.code == "" {
				if len(hooks.Diagnostics) != 0 {
					t.Fatalf("unexpected source gaps: %+v", hooks.Diagnostics)
				}
				return
			}
			if len(hooks.Diagnostics) != 1 {
				t.Fatalf("expected one source gap: %+v", hooks.Diagnostics)
			}
			if d := hooks.Diagnostics[0]; d.Code != tc.code || d.Path != "p/install.sh" || d.Line != tc.line || d.Column != max(tc.column, 1) || !d.AffectsScope {
				t.Fatalf("incorrect source gap: %+v", d)
			}
		})
	}
}

func TestHookSourceRejectsStateAfterUnsupportedCommands(t *testing.T) {
	for _, line := range []string{"eval 'printf ready' >out", "unset -f source >out", "declare -n helper=target"} {
		t.Run(line, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, line+"\nsource \"$PLUGIN_ROOT/lib.sh\"\n", "")
			if len(hooks.Paths) != 1 || hooks.Paths[0].Target != "p/install.sh" || len(hooks.Diagnostics) != 1 {
				t.Fatalf("unexpected paths or gaps: %+v", hooks)
			}
			if d := hooks.Diagnostics[0]; d.Code != "hook_source_command_unverified" || d.Path != "p/install.sh" || d.Line != 1 {
				t.Fatalf("incorrect source gap: %+v", d)
			}
		})
	}
}

func TestHookSourceBashReplacement(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, command, code string
		line                        int
	}{
		{
			name: "all five JSON escapes",
			prefix: `prepare() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  case "$s" in 'a\\b\"c\nd\re\tf\\g') source ./lib.sh ;; esac
}
prepare 'a\b"c
d` + "\r" + `e` + "\t" + `f\g'
`,
		},
		{name: "replace every occurrence", prefix: "helper=XX/libXXsh\n", command: `helper="${helper//XX/.}"`},
		{name: "unknown input preserves unrelated binding", prefix: "helper=./lib.sh\n", command: `result="${unknown//x/y}"`},
		{name: "unknown input forgets assigned binding", prefix: "helper=./lib.sh\n", command: `helper="${unknown//x/y}"`, code: "hook_source_dynamic", line: 3},
		{name: "dynamic replacement stays a barrier", prefix: "helper=./lib.sh\n", command: `result="${helper//x/${helper:=./other.sh}}"`, code: "hook_source_command_unverified", line: 2},
		{name: "glob patterns stay a barrier", prefix: "helper=./lib.sh\n", command: `result="${helper//*/other}"`, code: "hook_source_command_unverified", line: 2},
		{name: "match-reference replacement stays a barrier", prefix: "helper=./lib.sh\n", command: `result="${helper//x/&}"`, code: "hook_source_command_unverified", line: 2},
		{name: "tilde replacement stays a barrier", prefix: "helper=./lib.sh\n", command: `result="${helper//x/~}"`, code: "hook_source_command_unverified", line: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := tc.prefix
			if tc.command != "" {
				script += tc.command + "\nsource \"$helper\"\n"
			}

			hooks := analyzeHookSourceFlow(t, script, "")
			if tc.code == "" {
				if len(hooks.Diagnostics) != 0 || len(hooks.Paths) < 2 || hooks.Paths[len(hooks.Paths)-1].Target != "p/lib.sh" {
					t.Fatalf("expected resolved source ./lib.sh: %+v", hooks)
				}

				return
			}

			if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != tc.code || hooks.Diagnostics[0].Line != tc.line {
				t.Fatalf("incorrect source gap: %+v", hooks.Diagnostics)
			}
		})
	}
}

func TestHookSourceFunctionRecursion(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nprepare\n", "prepare() {\n  prepare\n}\n")
	if len(hooks.Diagnostics) != 1 {
		t.Fatalf("expected one source gap: %+v", hooks.Diagnostics)
	}
	if d := hooks.Diagnostics[0]; d.Code != "hook_source_cycle" || d.Path != "p/paths.sh" || d.Line != 2 || d.Column != 3 {
		t.Fatalf("incorrect function cycle: %+v", d)
	}
}

func TestHookSourceBun(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		linked       bool
	}{
		{name: "literal executable", script: `bun "$PLUGIN_ROOT/relay.ts"`, linked: true},
		{name: "lookup with a home-directory fallback", script: `runtime="$(command -v bun 2>/dev/null)"
[ -z "$runtime" ] && [ -x "$HOME/.bun/bin/bun" ] && runtime="$HOME/.bun/bin/bun"
[ -z "$runtime" ] && exit 0
exec "$runtime" "$PLUGIN_ROOT/relay.ts"`, linked: true},
		{name: "variable overwritten", script: "runtime=\"$(command -v bun)\"\nruntime=\"$other\"\nexec \"$runtime\" \"$PLUGIN_ROOT/relay.ts\""},
		{name: "shadowed lookup", script: "command() { printf other; }\nruntime=\"$(command -v bun)\"\nexec \"$runtime\" \"$PLUGIN_ROOT/relay.ts\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, tc.script, "", artifact.NewFile("p/relay.ts", []byte("console.log(1)\n"), false))
			linked := slices.ContainsFunc(hooks.Paths, func(p hooktrace.Path) bool {
				return p.Target == "p/relay.ts" && p.Language == "typescript"
			})
			gap := slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool {
				return d.Code == "hook_source_bun_scope_unverified" && d.AffectsScope
			})
			if linked != tc.linked || gap != tc.linked {
				t.Fatalf("Bun target linked = %v and scope gap = %v, want both %v; %+v", linked, gap, tc.linked, hooks)
			}
		})
	}
}

func analyzeHookSourceFlow(t *testing.T, install, pathsScript string, extra ...artifact.File) hooktrace.Sources {
	t.Helper()
	files := []artifact.File{
		artifact.NewFile("p/.codex-plugin/plugin.json", []byte(`{"name":"example"}`), false),
		artifact.NewFile("p/hooks/hooks.json", []byte(`{"SessionStart":[{"hooks":[{"type":"command","command":"cd \"$PLUGIN_ROOT\" && bash ./install.sh"}]}]}`), false),
		artifact.NewFile("p/install.sh", []byte(install), false),
		artifact.NewFile("p/paths.sh", []byte(pathsScript), false),
		artifact.NewFile("p/base.sh", []byte("base=\"$PLUGIN_ROOT\"\n"), false),
		artifact.NewFile("p/shift.sh", []byte("shift\n"), false),
		artifact.NewFile("p/lib.sh", []byte("printf root\n"), false),
		artifact.NewFile("p/other.sh", []byte("printf other\n"), false),
		artifact.NewFile("p/sub/lib.sh", []byte("printf sub\n"), false),
	}
	files = slices.Concat(files, extra)
	inventory := make([]report.File, 0, len(files))
	for _, file := range files {
		inventory = append(inventory, file.Metadata())
	}
	_, _, hooks := harness.DiscoverWithHookSources(t.Context(), inventory, document.PrepareAll(t.Context(), files), report.ExtractionReport{}, report.HarnessOptions{})
	return hooks
}
