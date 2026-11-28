package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestPortableCodexOverlayPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, inline, chosen string
		manifests            []string
	}{
		{"compatibility fallback", "", "compat.json", []string{"plugin.json", ".codex-plugin/plugin.json"}},
		{"inline wins", `,"extensions":{"com.openai":{"hooks":"./inline.json"}}`, "inline.json", []string{"plugin.json"}},
		{"empty inline blocks fallback", `,"extensions":{"com.openai":{}}`, "hooks/hooks.json", []string{"plugin.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"plugin.json":               `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"portable"` + tc.inline + `}`,
				".codex-plugin/plugin.json": `{"name":"compat","hooks":"./compat.json","skills":"./legacy","mcpServers":"./.mcp.json"}`,
				"compat.json":               `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo compat"}]}]}}`,
				"inline.json":               `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo inline"}]}]}}`,
				"hooks/hooks.json":          `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo default"}]}]}}`,
				"legacy/ignored/SKILL.md":   "Legacy skill.",
				".mcp.json":                 `{"mcpServers":{"legacy":{"command":"ignored"}}}`,
				"mcp.json":                  `{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{"portable":{"type":"stdio","command":"example-tool"}}}`,
			}
			g := inspect(t, files, report.HostCodex)
			if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostCodex || !slices.Equal(g.Plugins[0].Manifests, tc.manifests) {
				t.Fatalf("plugin interpretations: %+v", g.Plugins)
			}
			for _, n := range g.Components {
				if n.PluginID == "" {
					continue
				}
				switch n.Kind {
				case report.ComponentHook:
					if n.Activation != "inactive_for_profile" && n.Path != tc.chosen {
						t.Errorf("unexpected active hook: %+v", n)
					}
				case report.ComponentMCPConfig:
					if n.Path != "mcp.json" {
						t.Errorf("legacy MCP loaded: %+v", n)
					}
				case report.ComponentSkill:
					t.Errorf("legacy skill loaded: %+v", n)
				}
			}
			if !hasNode(g, report.ComponentHook, tc.chosen, "conditional") || len(nodes(g, "mcp_server")) != 1 {
				t.Fatalf("chosen components missing: %+v", g.Components)
			}
		})
	}
}

func TestPortablePluginCoverageGaps(t *testing.T) {
	const manifest = `{"$schema":"https://agent-plugins.org/schemas/1.1.0/plugin.schema.json","name":"portable"}`
	const mcp = `{"$schema":"https://agent-plugins.org/schemas/1.1.0/mcp.schema.json","mcpServers":{"valid":{"type":"stdio","command":"example-tool"},"invalid":{"type":"stdio","command":"../outside"}}}`
	const hooks = `{"$schema":"https://agent-plugins.org/schemas/1.1.0/hooks.schema.json","hooks":{"SessionStart":[{"command":"wrong two tokens"},{"command":"/"},{"command":"./bad\u0001name"},{"command":"example-hook"}],"InvalidEvent":[{"command":"example-hook"}]}}`
	files := map[string]string{"plugin.json": manifest, "mcp.json": mcp, "hooks.json": hooks, "skills/demo/SKILL.md": "Test skill."}
	g := inspect(t, files, report.HostAuto)
	if len(nodes(g, "mcp_server")) != 1 || len(nodes(g, report.ComponentHook)) != 1 ||
		!hasIssue(g, "portable_mcp_server_invalid") || !hasIssue(g, "portable_hooks_config_invalid") {
		t.Fatalf("invalid entries hid valid siblings or gaps: %+v", g)
	}

	files["mcp.json"] = `{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{"valid":{"type":"stdio","command":"example-tool"}}}`
	g = inspect(t, files, report.HostAuto)
	if len(nodes(g, "mcp_server")) != 0 || len(nodes(g, report.ComponentHook)) != 1 || !hasIssue(g, "portable_mcp_config_invalid") {
		t.Fatalf("version mismatch did not isolate MCP: %+v", g)
	}

	files["plugin.json"] = `{"$schema":"https://agent-plugins.org/schemas/9.0.0/plugin.schema.json","name":"portable"}`
	files[".codex-plugin/plugin.json"] = `{"name":"compat"}`
	g = inspect(t, files, report.HostCodex)
	if len(g.Plugins) != 1 || !hasIssue(g, "portable_plugin_version_unsupported") || !slices.Equal(g.Plugins[0].Manifests, []string{"plugin.json"}) {
		t.Fatalf("unknown schema fell back to a legacy manifest: %+v", g)
	}
}
