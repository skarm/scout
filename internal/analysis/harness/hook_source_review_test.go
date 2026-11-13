package harness_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/harness"
)

func TestHookSourceRestoresPositionalsAfterExplicitArguments(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh ./lib.sh\n", "source ./base.sh ./other.sh\nsource \"$1\"\n")
	assertHookTerminalPath(t, hooks, "p/lib.sh")
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

func assertHookTerminalPath(t *testing.T, hooks harness.HookSources, want string) {
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
