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
