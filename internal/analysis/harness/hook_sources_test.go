package harness_test

import (
	"encoding/json"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

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
		{"source pipeline", `bash "$PLUGIN_ROOT/install.sh"`, "# line\nsource \"$PLUGIN_ROOT/lib.sh\" | cat\n", "hook_source_control_unverified", 1},
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

func TestHookSourceFlow(t *testing.T) {
	for _, tc := range []struct {
		name, install, pathsScript, want, code string
		line                                   int
	}{
		{name: "constant from source", install: ". \"$PLUGIN_ROOT/paths.sh\"\nsource \"$helper\"\n", pathsScript: "base=\"$PLUGIN_ROOT\"\nexport helper=\"$base/lib.sh\"\n", want: "p/lib.sh"},
		{name: "nested constants", install: ". \"$PLUGIN_ROOT/paths.sh\"\nsource \"$helper\"\n", pathsScript: "source \"$PLUGIN_ROOT/base.sh\"\nhelper=\"$base/lib.sh\"\n", want: "p/lib.sh"},
		{name: "unknown reassignment", install: ". \"$PLUGIN_ROOT/paths.sh\"\nhelper=\"$unresolved\"\nsource \"$helper\"\n", pathsScript: "helper=\"$PLUGIN_ROOT/lib.sh\"\n", code: "hook_source_dynamic", line: 3},
		{name: "same path", install: "if test a = b; then helper=./lib.sh; else helper=./lib.sh; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
		{name: "different paths", install: "if test a = b; then helper=./lib.sh; else helper=./other.sh; fi\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "implicit else", install: "if test a = b; then helper=./lib.sh; fi\nsource \"$helper\"\n", code: "hook_source_dynamic", line: 2},
		{name: "same paths after nested branches", install: "if test a = b; then helper=./lib.sh; elif test a = c; then helper=./lib.sh; else helper=./lib.sh; fi\nsource \"$helper\"\n", want: "p/lib.sh"},
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
		{name: "function arguments stop after dynamic expansion", install: "source ./paths.sh\nprepare $unknown ./lib.sh\nsource \"$helper\"\n", pathsScript: "prepare() { helper=\"$2\"; }\n", code: "hook_source_dynamic", line: 3},
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
		{name: "negated directory change is unverified", install: "! cd ./sub\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
		{name: "piped directory change is unverified", install: "cd ./sub | cat\nsource ./lib.sh\n", code: "hook_source_command_unverified", line: 2},
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
			if d := hooks.Diagnostics[0]; d.Code != tc.code || d.Path != "p/install.sh" || d.Line != tc.line || d.Column != 1 || !d.AffectsScope {
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

func TestHookSourceFunctionRecursion(t *testing.T) {
	hooks := analyzeHookSourceFlow(t, "source ./paths.sh\nprepare\n", "prepare() {\n  prepare\n}\n")
	if len(hooks.Diagnostics) != 1 {
		t.Fatalf("expected one source gap: %+v", hooks.Diagnostics)
	}
	if d := hooks.Diagnostics[0]; d.Code != "hook_source_cycle" || d.Path != "p/paths.sh" || d.Line != 2 || d.Column != 3 {
		t.Fatalf("incorrect function cycle: %+v", d)
	}
}

func analyzeHookSourceFlow(t *testing.T, install, pathsScript string) harness.HookSources {
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
	inventory := make([]report.File, 0, len(files))
	for _, file := range files {
		inventory = append(inventory, file.Metadata())
	}
	_, _, hooks := harness.DiscoverWithHookSources(t.Context(), inventory, document.PrepareAll(t.Context(), files), report.ExtractionReport{}, report.HarnessOptions{})
	return hooks
}
