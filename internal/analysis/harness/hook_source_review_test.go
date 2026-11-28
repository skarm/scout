package harness_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/hooktrace"
)

func TestHookSourceRestoresPositionalsAfterExplicitArguments(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh ./lib.sh\n", "source ./base.sh ./other.sh\nsource \"$1\"\n")
	assertHookTerminalPath(t, hooks, "p/lib.sh")
}

func TestHookSourceTracesCaseInRuntimeArrayLoop(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, `
patterns=(first)
patterns+=("$extra_pattern")
helper=./other.sh
for pattern in "${patterns[@]}"; do
  case "$input" in
    $pattern|*/$pattern) helper=./lib.sh ;;
  esac
done
case "$helper" in
  ./lib.sh) source ./lib.sh ;;
  ./other.sh) source ./other.sh ;;
esac
`, "")
	targets := make(map[string]bool)
	for _, p := range hooks.Paths {
		targets[p.Target] = true
	}
	if len(hooks.Diagnostics) != 0 || !targets["p/lib.sh"] || !targets["p/other.sh"] {
		t.Fatalf("expected both loop outcomes: %+v", hooks)
	}
}

func TestHookSourceKeepsUnchangedBindingsAcrossRedirectedAssignment(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
helper=./lib.sh
payload=$(cat) 2>/dev/null
source "$helper"
`, ""), "p/lib.sh")

	hooks := analyzeHookSourceFlow(t, `
helper=./lib.sh
helper=./other.sh 2>/dev/null
source "$helper"
`, "")
	if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
		t.Fatalf("expected unknown assignment status: %+v", hooks)
	}
}

func TestHookSourceRetainsPathsAfterReadOnlyShellOperations(t *testing.T) {
	for _, tc := range []struct{ name, command string }{
		{"git directory probe", `git rev-parse --git-dir >/dev/null 2>&1 || exit 0`},
		{"quoted whitespace deletion", `[[ -z "${incoming//[[:space:]]/}" ]] && exit 0`},
		{"cleanup with option separator", `trap 'rm -rf -- "$scratch"' EXIT`},
		{"positionals from runtime text", `set -- $incoming`},
		{"array read from runtime text", `read -ra words <<< "$incoming"`},
		{"glob matching options", `shopt -s dotglob nullglob`},
		{"lexical ordering", `[[ "$today" < "$expires" ]] 2>/dev/null || exit 0`},
		{"file ordering", `[[ "$newer" -nt "$older" ]] && exit 0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "helper=./lib.sh\n" + tc.command + "\nsource \"$helper\"\n"
			assertHookTerminalPath(t, analyzeHookSourceFlow(t, script, ""), "p/lib.sh")
		})
	}
}

func TestHookSourceReturnWithStatusPreservesReachablePaths(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
prepare() {
  false
  return "$?"
  source ./missing.sh
}
prepare
source ./lib.sh
`, ""), "p/lib.sh")

	hooks := analyzeHookSourceFlow(t, `
prepare() {
  (exit 123)
  return $?
  source ./other.sh
}
IFS=2
prepare
source ./lib.sh
`, "")
	assertHookTerminalPath(t, hooks, "p/lib.sh")

	for _, p := range hooks.Paths {
		if p.Target == "p/other.sh" {
			return
		}
	}

	t.Fatalf("a split status can leave the command after return reachable: %+v", hooks)
}

func TestHookSourceCountsGitPathsWithDiscardedStderr(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
count=$(git -C "$project" diff --name-only 2>/dev/null | wc -l | tr -d ' ')
(( count > 0 )) && source ./lib.sh
`, ""), "p/lib.sh")
}

func TestHookSourceTracesReadLoopThatAppendsData(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
while IFS= read -r line; do
  [ -n "$line" ] || continue
  printf '%s\n' "$line" >> "$log"
done <<< "$input"
source "$PLUGIN_ROOT/lib.sh"
`, ""), "p/lib.sh")
}

func TestHookSourceTracesReadLoopWithLoggingHelper(t *testing.T) {
	const loop = `
record() { write_log "$@"; }
while IFS= read -r line; do
  record "$line"
done <<< "$input"
source "$PLUGIN_ROOT/lib.sh"
`
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `write_log() { printf '%s\n' "$*" >> "$log"; }`+loop, ""), "p/lib.sh")

	for _, definition := range []string{
		`write_log() { printf -v helper '%s' "$*" >> "$log"; }`,
		`printf() { source ./other.sh; }
write_log() { printf '%s\n' "$*" >> "$log"; }`,
	} {
		hooks := analyzeHookSourceFlow(t, definition+loop, "")
		if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
			t.Fatalf("expected a coverage gap for %s: %+v", definition, hooks)
		}
	}
}

func TestHookSourceTracesFileCopyLoop(t *testing.T) {
	const loop = `
for item in "$directory"/*.txt; do
  [ -f "$item" ] || continue
  name=$(basename "$item")
  cmp -s "$item" "$destination/$name" 2>/dev/null || cp "$item" "$destination/$name" 2>/dev/null
done
source "$PLUGIN_ROOT/lib.sh"
`
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, loop, ""), "p/lib.sh")

	for _, name := range []string{"cmp", "cp"} {
		t.Run(name, func(t *testing.T) {
			hooks := analyzeHookSourceFlow(t, name+"() { source ./other.sh; }\n"+loop, "")
			if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
				t.Fatalf("expected a gap when the loop command is shadowed: %+v", hooks)
			}
		})
	}
}

func TestHookSourceTracesCaseWithDiscardedOutput(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
case match in
  match) source ./lib.sh ;;
  *) source ./missing.sh ;;
esac 2>/dev/null
`, ""), "p/lib.sh")
}

func TestHookSourceTracesGuardedCallbackWithDifferentAction(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, `
visit() {
  case "$1" in
    one) source ./lib.sh ;;
    many)
      for item in "$directory"/*.txt; do
        [ -f "$item" ] || continue
        visit one "$item" || continue
      done
      ;;
  esac
}
visit many
`, ""), "p/lib.sh")
}

func TestHookSourceDoesNotSkipShadowedContinue(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, `
visit() { continue() { source ./missing.sh; }; }
for item in "$directory"/*.txt; do
  [ -f "$item" ] || continue
  visit "$item" || continue
done
`, "")
	if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
		t.Fatalf("a redefined loop command must leave a coverage gap: %+v", hooks)
	}
}

func TestHookSourceSetReplacesKnownPositionals(t *testing.T) {
	assertHookTerminalPath(t, analyzeHookSourceFlow(t, "set -- ./lib.sh\nsource \"$1\"\n", ""), "p/lib.sh")

	hooks := analyzeHookSourceFlow(t, "set -- ./lib.sh\nset -- $incoming\nsource \"$1\"\n", "")
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			t.Fatalf("set retained a stale positional operand: %+v", hooks)
		}
	}

	if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
		t.Fatalf("expected an unresolved runtime operand: %+v", hooks)
	}
}

func TestHookSourceFunctionCanBeImportedByEitherBranch(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "if test -n \"$mode\"; then source ./paths.sh; else . ./paths.sh; fi\nprepare\n", "prepare() { source ./lib.sh; }\n")
	var count int
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			count++
			if len(p.Steps) != 4 || p.Steps[1].Path != "p/install.sh" || p.Steps[2].Path != "p/install.sh" || p.Steps[3].Path != "p/paths.sh" {
				t.Fatalf("incorrect provenance: %+v", p.Steps)
			}
		}
	}
	if count != 2 || len(hooks.Diagnostics) != 0 {
		t.Fatalf("expected one path for each import: %+v", hooks)
	}
}

func TestHookSourceTracesAllDefiniteFunctionChoices(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, `
if [ -n "$mode" ]; then
  prepare() { source ./lib.sh; }
else
  prepare() { source ./other.sh; }
fi
fn=prepare
"$fn"
runner=sh
"$runner" ./base.sh
`, "")
	targets := make(map[string]bool)
	for _, p := range hooks.Paths {
		targets[p.Target] = true
	}

	if len(hooks.Diagnostics) != 0 || !targets["p/lib.sh"] || !targets["p/other.sh"] || !targets["p/base.sh"] {
		t.Fatalf("known dispatch targets were lost: %+v", hooks)
	}
}

func TestHookSourceDoesNotApplySkippedOrAssignment(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "helper=./lib.sh\ntrue || helper=./other.sh\nsource \"$helper\"\n", "")
	assertHookTerminalPath(t, hooks, "p/lib.sh")
}

func TestHookSourceDoesNotUseStaleArithmeticAssignment(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nsource \"$helper\"\n", "helper=./lib.sh\nprintf '%s' \"$((helper=1))\"\n")
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			t.Fatalf("arithmetic expansion left a stale binding: %+v", hooks)
		}
	}
	if len(hooks.Diagnostics) == 0 || !hooks.Diagnostics[0].AffectsScope {
		t.Fatalf("missing diagnostic: %+v", hooks)
	}
}

func assertHookTerminalPath(t *testing.T, hooks hooktrace.Sources, want string) {
	t.Helper()

	if len(hooks.Diagnostics) != 0 || len(hooks.Paths) == 0 || hooks.Paths[len(hooks.Paths)-1].Target != want {
		t.Fatalf("expected final target %q: %+v", want, hooks)
	}
}

func TestHookSourceAndOrPreservesConditionalEffects(t *testing.T) {
	for _, tc := range []struct {
		name, script, want string
	}{
		{"mixed list", "false && helper=./other.sh || helper=./lib.sh\nsource \"$helper\"\n", "p/lib.sh"},
		{"if status", "if true || false; then helper=./lib.sh; else helper=./other.sh; fi\nsource \"$helper\"\n", "p/lib.sh"},
		{"guarded directory", "if cd ./sub && true; then source ./lib.sh; fi\n", "p/sub/lib.sh"},
		{"background list", "helper=./lib.sh\ntrue && helper=./other.sh &\nsource \"$helper\"\n", "p/lib.sh"},
		{"background negated list", "helper=./lib.sh\n! false && helper=./other.sh &\nsource \"$helper\"\n", "p/lib.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertHookTerminalPath(t, analyzeHookSourceFlow(t, tc.script, ""), tc.want)
		})
	}
}

func TestHookSourceFunctionsUseTheDefinitionActiveAtTheCall(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nprepare\n", "prepare() { source ./lib.sh; }\nprepare() { source ./other.sh; }\n")
	assertHookTerminalPath(t, hooks, "p/other.sh")
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			t.Fatalf("superseded function was called: %+v", hooks)
		}
	}
}

func TestHookSourceExportAppendDoesNotReplaceExistingValue(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nsource \"$helper\"\n", "helper=./sub/\nexport helper+=./lib.sh\n")
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			t.Fatalf("append treated as replacement: %+v", hooks)
		}
	}
	if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_dynamic" || hooks.Diagnostics[0].Line != 2 {
		t.Fatalf("missing diagnostic for unresolved append: %+v", hooks)
	}
}

func TestHookSourceDoesNotCallSupersededFunctionAfterRedirectedDefinition(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nprepare\n", "prepare() { source ./lib.sh; }\nprepare() { :; } >output\n")
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" {
			t.Fatalf("superseded function was called: %+v", hooks)
		}
	}
	if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_control_unverified" ||
		hooks.Diagnostics[0].Path != "p/paths.sh" || hooks.Diagnostics[0].Line != 2 {
		t.Fatalf("missing diagnostic for redirected body: %+v", hooks)
	}
}

func TestHookSourceDoesNotRestoreArgsThatMayBeOmitted(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh ./lib.sh ./other.sh\n", "source ./shift.sh $maybe\nsource \"$1\"\n")
	// An unquoted argument can disappear, making the sourced shift affect
	// the caller rather than a temporary positional scope.
	for _, p := range hooks.Paths {
		if p.Target == "p/lib.sh" || p.Target == "p/other.sh" {
			t.Fatalf("unverified source arguments selected a target: %+v", hooks)
		}
	}
	if len(hooks.Diagnostics) != 1 || hooks.Diagnostics[0].Code != "hook_source_dynamic" || hooks.Diagnostics[0].Line != 2 {
		t.Fatalf("missing source diagnostic: %+v", hooks)
	}
}

func TestHookSourceReturnWithNumericStatusPreservesState(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nsource \"$helper\"\n", "helper=./lib.sh\nreturn 0\nhelper=./other.sh\n")
	assertHookTerminalPath(t, hooks, "p/lib.sh")
}

func TestHookSourceShiftLoopTracesAssignmentsBehindReadOnlyGuards(t *testing.T) {
	const loop = `
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) mode="$2"; shift 2 ;;
    *) if [ -z "$mode" ]; then mode="$1"; fi; shift ;;
  esac
done
source ./lib.sh
`

	for _, args := range []string{"set -- test\n", `set -- "$runtime"` + "\n"} {
		hooks := analyzeHookSourceFlow(t, args+loop, "")
		assertHookTerminalPath(t, hooks, "p/lib.sh")
	}

	shadowed := analyzeHookSourceFlow(t, "test() { eval \"$1\"; }\nset -- test\n"+
		strings.Replace(loop, `[ -z "$mode" ]`, `test -z "$mode"`, 1), "")
	if len(shadowed.Diagnostics) == 0 {
		t.Fatalf("function shadowing a predicate left no coverage gap: %+v", shadowed)
	}
}

func TestHookSourceKeepsTracedBranchWhenAnotherBranchIsBlocked(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, `
helper=./other.sh
if [ -n "$mode" ]; then
  "$dynamic_dispatch"
else
  helper=./lib.sh
fi
source "$helper"
`, "")

	var traced bool
	for _, p := range hooks.Paths {
		if p.Target == "p/other.sh" {
			t.Fatalf("blocked branch supplied an unsupported source path: %+v", hooks)
		}

		traced = traced || p.Target == "p/lib.sh"
	}

	if !traced || len(hooks.Diagnostics) != 1 || !hooks.Diagnostics[0].AffectsScope {
		t.Fatalf("expected a traced branch and a coverage gap: %+v", hooks)
	}
}
