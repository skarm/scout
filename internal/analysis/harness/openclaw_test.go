package harness_test

import (
	"testing"

	"github.com/skarm/scout/report"
)

func TestOpenClawNativePackageBindsCapturedEntriesAndHooks(t *testing.T) {
	const manifest = "openclaw.plugin.json"
	g := inspect(t, map[string]string{
		manifest:                      `{id:'fixture',configSchema:{},skills:['skills']}`,
		"package.json":                `{"openclaw":{"extensions":["./src/plugin.ts","../outside.ts"],"hooks":["./hook-pack/report"],"setupEntry":"./src/setup.ts"}}`,
		"src/plugin.ts":               "export default {}\n",
		"src/setup.ts":                "export default {}\n",
		"skills/format/SKILL.md":      "Format plain text.\n",
		"hook-pack/report/HOOK.md":    "---\nname: report\n---\nReport an event.\n",
		"hook-pack/report/handler.ts": "export default () => {}\n",
		"hook-pack/report/handler.js": "export default () => {}\n",
	}, report.HostAuto)
	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostOpenClaw || len(g.Plugins[0].Manifests) != 1 || g.Plugins[0].Manifests[0] != manifest {
		t.Fatalf("invalid package interpretation: %+v", g.Plugins)
	}

	for _, item := range []struct{ kind, path string }{
		{"handler", "src/plugin.ts"},
		{"handler", "src/setup.ts"},
		{report.ComponentSkill, "skills/format/SKILL.md"},
		{report.ComponentHook, "hook-pack/report/HOOK.md"},
		{"handler", "hook-pack/report/handler.ts"},
	} {
		if !hasNode(g, item.kind, item.path, "") {
			t.Errorf("missing %s %s", item.kind, item.path)
		}
	}

	if hasNode(g, "handler", "hook-pack/report/handler.js", "") || !hasReference(g, report.ReferenceUnresolved, "outside_package") {
		t.Fatalf("invalid handler precedence or escaping path: %+v", g.References)
	}
}

func TestOpenClawSettingsAndStandaloneHookStaySourceBound(t *testing.T) {
	g := inspect(t, map[string]string{
		"openclaw.json":          `{mcp:{servers:{saved:{url:'https://example.invalid/mcp',enabled:false}}}, agents:{$include:'outside.json5'}}`,
		"hooks/example/HOOK.md":  "# Example hook\n",
		"hooks/example/index.js": "export default () => {}\n",
		"outside.json5":          `{mcp:{servers:{elsewhere:{url:'https://example.invalid/other'}}}}`,
	}, report.HostAuto)

	if !hasNode(g, "mcp_server", "openclaw.json", "inactive_for_profile") ||
		!hasNode(g, report.ComponentHook, "hooks/example/HOOK.md", "") ||
		!hasNode(g, "handler", "hooks/example/index.js", "") || len(nodes(g, "mcp_server")) != 1 ||
		!hasReference(g, report.ReferenceUnresolved, "openclaw_config_include_unresolved") {
		t.Fatalf("unexpected OpenClaw graph: %+v", g)
	}
}
