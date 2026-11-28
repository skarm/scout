package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestQwenExtensionResolvesContainedDeclarations(t *testing.T) {
	const manifest = "qwen-extension.json"
	g := inspect(t, map[string]string{
		manifest: `{"name":"formatter","version":"1.0.0","hooks":"config/events.json",
			"mcpServers":{"local":{"command":"node","args":["${extensionPath}${/}dist${pathSeparator}server.js"]}},
			"lspServers":"config/lsp.json","contextFileName":"CONTEXT.md",
			"commands":"prompts","skills":"recipes","workflows":["tasks","extras/task.js"],
			"channels":{"local":{"entry":"dist/channel.js"},"outside":{"entry":"../outside.js"}}}`,
		"config/events.json":         `{"SessionStart":[{"hooks":[{"type":"command","command":"printf ready"}]}]}`,
		"hooks/hooks.json":           `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf unused"}]}]}}`,
		"config/lsp.json":            `{"local":{"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/dist/server.js"]}}`,
		"dist/server.js":             "console.log('ready')\n",
		"dist/channel.js":            "export const plugin = {}\n",
		"CONTEXT.md":                 "Format content.\n",
		"QWEN.md":                    "Superseded context.\n",
		"prompts/fs/review.toml":     "prompt = 'Review text.'\n",
		"recipes/format/SKILL.md":    "Format text.\n",
		"recipes/deep/nope/SKILL.md": "Nested skill.\n",
		"tasks/review.js":            "export const meta = {name: 'review'}\n",
		"extras/task.js":             "export const meta = {name: 'task'}\n",
		"tasks/nested/ignored.js":    "export const meta = {name: 'ignored'}\n",
		"plugin.json":                `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"portable"}`,
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostQwenCode || !slices.Equal(g.Plugins[0].Manifests, []string{manifest}) {
		t.Fatalf("unexpected Qwen extension interpretations: %+v", g.Plugins)
	}

	for _, item := range []struct{ kind, path string }{
		{"mcp_server", manifest},
		{"lsp_server", "config/lsp.json"},
		{report.ComponentHook, "config/events.json"},
		{"handler", "dist/server.js"},
		{"channel", "dist/channel.js"},
		{"rule", "CONTEXT.md"},
		{"command", "prompts/fs/review.toml"},
		{report.ComponentSkill, "recipes/format/SKILL.md"},
		{"workflow", "tasks/review.js"},
		{"workflow", "extras/task.js"},
	} {
		if !slices.ContainsFunc(g.Components, func(c report.Component) bool {
			return c.Host == report.HostQwenCode && c.Kind == item.kind && c.Path == item.path && c.Source != nil
		}) {
			t.Errorf("missing %s at %s", item.kind, item.path)
		}
	}

	for _, c := range g.Components {
		if c.Host == report.HostQwenCode && slices.Contains([]string{"hooks/hooks.json", "QWEN.md", "tasks/nested/ignored.js", "recipes/deep/nope/SKILL.md"}, c.Path) {
			t.Errorf("unexpected Qwen component: %+v", c)
		}
	}
	if !slices.ContainsFunc(g.References, func(r report.ComponentReference) bool {
		return r.Kind == "component_path" && r.Status == report.ReferenceUnresolved && r.Source.Path == manifest
	}) {
		t.Error("missing unresolved reference to the external channel")
	}
}

func TestQwenPortableLoadsOnlySupportedComponents(t *testing.T) {
	const base = "fixture/.qwen/extensions/portable/"
	g := inspect(t, map[string]string{
		base + "plugin.json": `{"$schema":"https://agent-plugins.org/schemas/1.1.0/plugin.schema.json","name":"portable"}`,
		base + "mcp.json": `{"$schema":"https://agent-plugins.org/schemas/1.1.0/mcp.schema.json","mcpServers":{
			"local":{"type":"stdio","command":"printf"},"remote":{"type":"streamable-http","url":"https://example.invalid/mcp"},
			"legacy":{"type":"sse","url":"https://example.invalid/sse"}}}`,
		base + "hooks.json":             `{"$schema":"https://agent-plugins.org/schemas/1.1.0/hooks.schema.json","hooks":{"SessionStart":[{"command":"printf"}]}}`,
		base + ".mcp.json":              `{"mcpServers":{"native-only":{"command":"printf"}}}`,
		base + "commands/local.md":      "Local command.\n",
		base + "skills/format/SKILL.md": "Format text.\n",
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostQwenCode || len(nodes(g, "mcp_server")) != 2 ||
		len(nodes(g, report.ComponentHook)) != 0 || len(nodes(g, "command")) != 0 ||
		!slices.ContainsFunc(g.Components, func(c report.Component) bool {
			return c.Host == report.HostQwenCode && c.Kind == report.ComponentSkill && c.Path == base+"skills/format/SKILL.md"
		}) {
		t.Fatalf("unexpected Qwen portable declarations: %+v", g)
	}
}

func TestQwenWorkspaceKeepsUnknownHooksOutOfActivationGraph(t *testing.T) {
	const settings = ".qwen/settings.json"
	g := inspect(t, map[string]string{
		settings: `{// Local declarations remain visible when disabled.
			"disableAllHooks": true, "hooks": {"disabled": ["named-check"],
				"TodoCompleted":[{"hooks":[{"type":"http","url":"https://example.invalid/hook"}]}],
				"InstructionsLoaded":[{"hooks":[{"type":"prompt","prompt":"Check format."}]}],
				"BeforeTool":[{"hooks":[{"type":"command","command":"printf ignored"}]}]}}
		`,
		".mcp.json":                  `{"mcpServers":{"remote":{"httpUrl":"https://example.invalid/mcp"}}}`,
		".lsp.json":                  `{"local":{"command":"clangd"}}`,
		".qwen/commands/fs/check.md": "Check format.\n",
		".qwen/agents/review.yaml":   "name: review\n",
		"AGENTS.md":                  "Review formatting.\n",
	}, report.HostAuto)

	hooks := nodes(g, report.ComponentHook)
	if len(hooks) != 2 || slices.ContainsFunc(hooks, func(c report.Component) bool {
		return c.Host != report.HostQwenCode || c.Activation != "inactive_for_profile"
	}) || !hasNode(g, "mcp_server", ".mcp.json", "") || !hasNode(g, "lsp_server", ".lsp.json", "") ||
		!hasNode(g, "command", ".qwen/commands/fs/check.md", "") || !hasNode(g, "agent", ".qwen/agents/review.yaml", "") ||
		!hasNode(g, "rule", "AGENTS.md", "") {
		t.Fatalf("incorrect Qwen workspace declarations: %+v", g)
	}
}

func TestQwenSettingsRejectTrailingCommas(t *testing.T) {
	g := inspect(t, map[string]string{
		".qwen/settings.json": `{// Comments are supported.
			"mcpServers":{"demo":{"command":"printf"},},
		}`,
	}, report.HostAuto)

	if len(nodes(g, "mcp_server")) != 0 {
		t.Fatalf("a Qwen settings file with trailing commas registered a server: %+v", g.Components)
	}
}
