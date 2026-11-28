package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

func TestOpenClawDiscoveryStateWorkspaceAndNativePackages(t *testing.T) {
	home, state, workspace := t.TempDir(), t.TempDir(), t.TempDir()
	discoverySkill(t, home, "unused-personal", "Unused in a relocated state.")
	writeNativeFixture(t, workspace, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, state, "openclaw.json", `{
		mcp: {servers: {docs:{command:'printf',args:['opaque-argument']}}},
		plugins: {entries:{example:{enabled:false}}},
		skills: {entries:{managed:{enabled:true}}},
		hooks: {internal:{entries:{report:{enabled:true}}}},
	}`)
	writeNativeFixture(t, state, "skills/managed/SKILL.md", "Format text.\n")
	writeNativeFixture(t, state, "hooks/report/HOOK.md", "Report the event.\n")
	writeNativeFixture(t, state, "hooks/report/handler.ts", "export default () => {}\n")
	writeNativeFixture(t, state, "workspace/skills/default-workspace/SKILL.md", "Format text.\n")
	writeNativeFixture(t, workspace, "skills/workspace/SKILL.md", "Format text.\n")
	writeNativeFixture(t, workspace, ".agents/skills/portable/SKILL.md", "Format text.\n")
	manifest := writeNativeFixture(t, workspace, ".openclaw/extensions/example/openclaw.plugin.json", `{id:'example',configSchema:{},skills:['custom-skills']}`)
	writeNativeFixture(t, workspace, ".openclaw/extensions/example/custom-skills/example/SKILL.md", "Format text.\n")
	writeNativeFixture(t, state, "extensions/pack-folder/package.json", `{"name":"@example/pack","openclaw":{"hooks":["./hooks/bundled"]}}`)
	writeNativeFixture(t, state, "extensions/pack-folder/hooks/bundled/HOOK.md", "Report the event.\n")
	writeNativeFixture(t, state, "extensions/pack-folder/hooks/bundled/handler.js", "export default () => {}\n")

	args := []string{"discover", "--agent", report.HostOpenClaw, "--home", home, "--openclaw-home", state, "--project", workspace, "--system=false"}
	code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete || strings.Contains(string(raw), "opaque-argument") {
		t.Fatalf("invalid OpenClaw inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"mcp-server/docs":         "user",
		"skill/managed":           "user",
		"hook/report":             "user",
		"skill/default-workspace": "project",
		"skill/workspace":         "project",
		"skill/portable":          "project",
		"plugin/example":          "plugin",
		"plugin/pack":             "plugin",
		"skill/example":           "plugin",
		"hook/bundled":            "plugin",
	}
	for _, item := range inventory.Components {
		key := item.Kind + "/" + item.Name
		if expected, ok := want[key]; !ok || item.Agent != report.HostOpenClaw || item.Scope != expected {
			t.Fatalf("unexpected component: %+v", item)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing OpenClaw components: %v", want)
	}

	if !slices.Contains(inventory.Targets, filepath.Dir(manifest)) || len(inventory.Enablement) != 3 ||
		!slices.ContainsFunc(inventory.Enablement, func(e discovery.Enablement) bool {
			return e.Kind == "plugin" && e.Selector == "example" && e.State == "disabled" && e.Key == "/plugins/entries/example/enabled"
		}) {
		t.Fatalf("package target or its enablement missing: %+v", inventory)
	}
	if code, _ := runCheckpoint(t, append(slices.Clone(args), "--output", manifest)); code != 2 {
		t.Fatal("OpenClaw package manifest was not protected from report output")
	}
}

func TestOpenClawDiscoveryDoesNotFollowConfigIncludes(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	other := writeNativeFixture(t, home, "outside.json5", "{mcp:{servers:{should_not_appear:{command:'printf'}}}}")
	writeNativeFixture(t, state, "openclaw.json", `{agents:{$include:`+quoted(other)+`}}`)
	code, raw := runCheckpoint(t, []string{"discover", "--agent", report.HostOpenClaw, "--home", home, "--openclaw-home", state, "--no-project", "--system=false", "--format", "json"})
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 2 || inventory.Complete || len(inventory.Sources) != 1 || len(inventory.Issues) != 1 ||
		inventory.Issues[0].Code != "openclaw_include_unresolved" || strings.Contains(string(raw), other) {
		t.Fatalf("OpenClaw include widened discovery: exit %d: %s", code, raw)
	}
}

func quoted(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func TestOpenClawExtensionSnapshotTracksEntrypointReplacement(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	const plugin = "extensions/demo/"
	writeNativeFixture(t, state, plugin+"openclaw.plugin.json", `{id:'demo',configSchema:{}}`)
	writeNativeFixture(t, state, plugin+"package.json", `{"openclaw":{"extensions":["./old.js"]}}`)
	old := writeNativeFixture(t, state, plugin+"old.js", "export default {}\n")
	checkpoint := filepath.Join(t.TempDir(), "before.json")
	args := []string{
		"discover", "--agent", report.HostOpenClaw, "--home", home, "--openclaw-home", state, "--no-project",
		"--system=false", "--kind", "plugin", "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--format", "json", "--scope", "selected",
	}
	if code, _ := runCheckpoint(t, args); code != 2 {
		t.Fatalf("expected a saved snapshot with partial static coverage, exit %d", code)
	}

	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	writeNativeFixture(t, state, plugin+"new.js", "export default {id: 'demo'}\n")
	writeNativeFixture(t, state, plugin+"package.json", `{"openclaw":{"extensions":["./new.js"]}}`)

	code, raw := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected"))
	result := comparisonResult(t, raw)
	if code != 2 || result.Before == result.After || len(result.Roots) != 1 || result.Roots[0].Change != "modified" {
		t.Fatalf("entrypoint replacement was not reported, exit %d: %+v", code, result.Roots)
	}

	for _, side := range []struct {
		doc  *report.Document
		file string
	}{{result.Previous, "old.js"}, {result.Current, "new.js"}} {
		assertNativeGraph(t, side.doc, report.HostOpenClaw, "handler")
		graph := side.doc.Run.Targets[0].Analysis.Components
		if !slices.ContainsFunc(graph.Components, func(c report.Component) bool {
			return c.Kind == "handler" && c.Path == side.file
		}) {
			t.Fatalf("missing captured entrypoint %s", side.file)
		}
	}
}
