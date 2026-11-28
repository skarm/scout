package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestKimiPluginUsesNativeManifestAndContainedLaunches(t *testing.T) {
	const manifest = "kimi.plugin.json"
	g := inspect(t, map[string]string{
		manifest: `{"name":"Example.tools@local","skills":["./recipes"],"commands":["./prompts","./other.md"],
			"hooks":[{"event":"TurnStarted","command":"node ./bin/check.js"},{"event":"Stop","command":"node \"${KIMI_PLUGIN_ROOT}/bin/stop.js\""}],
			"mcpServers":{"direct":{"command":"./bin/server.js","cwd":"./bin"},
				"runtime":{"command":"node","args":["./local.js"],"cwd":"./bin"},
				"remote":{"command":"./bin/remote.js","environment_id":"container"}},
			"systemPrompt":"Review changes.","systemPromptPath":"./SYSTEM.txt","sessionStart":{"skill":"review"},
			"skillInstructions":"Start with formatting."}`,
		".kimi-plugin/plugin.json":     `{"name":"shadowed","mcpServers":{"unused":{"command":"printf"}}}`,
		"agents/review/deep.md":        "Review formatting.\n",
		"commands/undeclared.md":       "Absent from the manifest.\n",
		"prompts/group/review.md":      "Review changes.\n",
		"other.md":                     "Review file.\n",
		"recipes/review/SKILL.md":      "Review changes.\n",
		"recipes/flat.md":              "Format a file.\n",
		"recipes/review.md":            "Shadowed by the directory skill.\n",
		"recipes/review/deep/SKILL.md": "A nested bundle.\n",
		"SYSTEM.txt":                   "Always inspect the diff.\n",
		"bin/check.js":                 "console.log('check')\n",
		"bin/stop.js":                  "console.log('stop')\n",
		"bin/server.js":                "console.log('server')\n",
		"bin/local.js":                 "console.log('local')\n",
		"bin/remote.js":                "console.log('remote')\n",
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostKimiCode || !slices.Equal(g.Plugins[0].Manifests, []string{manifest}) {
		t.Fatalf("unexpected Kimi manifest precedence: %+v", g.Plugins)
	}

	for _, item := range []struct{ kind, path string }{
		{"handler", "bin/check.js"},
		{"handler", "bin/stop.js"},
		{"handler", "bin/server.js"},
		{"handler", "bin/local.js"},
		{"rule", "SYSTEM.txt"},
		{"agent", "agents/review/deep.md"},
		{"command", "prompts/group/review.md"},
		{"command", "other.md"},
		{report.ComponentSkill, "recipes/review/SKILL.md"},
		{report.ComponentSkill, "recipes/flat.md"},
	} {
		if !slices.ContainsFunc(g.Components, func(node report.Component) bool {
			return node.Host == report.HostKimiCode && node.Kind == item.kind && node.Path == item.path
		}) {
			t.Errorf("missing %s at %s", item.kind, item.path)
		}
	}

	if len(nodes(g, "mcp_server")) != 3 || len(nodes(g, report.ComponentHook)) != 2 || len(nodes(g, "rule")) != 4 ||
		slices.ContainsFunc(g.Components, func(n report.Component) bool {
			return n.Host == report.HostKimiCode && slices.Contains([]string{"bin/remote.js", "commands/undeclared.md", "recipes/review.md", "recipes/review/deep/SKILL.md"}, n.Path)
		}) {
		t.Fatalf("incorrect Kimi declarations: %+v", g.Components)
	}
}

func TestKimiPluginOnlyUsesRootSkillAsImplicitFallback(t *testing.T) {
	g := inspect(t, map[string]string{
		"pkg/.kimi-plugin/plugin.json": `{"name":"fixture","commands":"../outside.md","systemPromptPath":"/tmp/outside.md"}`,
		"pkg/SKILL.md":                 "Root skill.\n",
		"pkg/skills/implicit/SKILL.md": "Outside the declared skill locations.\n",
		"outside.md":                   "Outside the package.\n",
	}, report.HostKimiCode)

	if !slices.ContainsFunc(g.Components, func(c report.Component) bool {
		return c.Host == report.HostKimiCode && c.Kind == report.ComponentSkill && c.Path == "pkg/SKILL.md"
	}) || slices.ContainsFunc(g.Components, func(c report.Component) bool {
		return c.Host == report.HostKimiCode && c.Kind == report.ComponentSkill && c.Path == "pkg/skills/implicit/SKILL.md"
	}) {
		t.Fatalf("unexpected Kimi default skills: %+v", g.Components)
	}
	refs := 0
	for _, r := range g.References {
		if r.Kind == "component_path" && r.Status == report.ReferenceUnresolved {
			refs++
		}
	}
	if refs != 2 || len(nodes(g, "command")) != 0 || len(nodes(g, "rule")) != 0 {
		t.Fatalf("unsafe package path appears materialized: %+v", g)
	}
}

func TestKimiWorkspaceConfigurationAndInstalledState(t *testing.T) {
	const config = ".kimi-code/config.toml"
	g := inspect(t, map[string]string{
		config:                              "[[hooks]]\nevent='PermissionResult'\ncommand='node ./helper.js'\n",
		".kimi-code/mcp.json":               `{"mcpServers":{"demo":{"transport":"sse","url":"https://example.invalid/sse","enabled":false}}}`,
		".kimi-code/plugins/installed.json": `{"version":1,"plugins":[{"id":"demo","root":"/sample/plugins/managed/demo","enabled":false}]}`,
		".kimi-code/skills/flat.md":         "Format text.\n",
		".kimi-code/agents/review.md":       "Review formatting.\n",
		".kimi-code/AGENTS.md":              "Repository instructions.\n",
		"helper.js":                         "console.log('ready')\n",
	}, report.HostAuto)

	if !hasNode(g, report.ComponentHook, config, "unknown") ||
		!hasNode(g, "mcp_server", ".kimi-code/mcp.json", "inactive_for_profile") ||
		!hasNode(g, "extension", ".kimi-code/plugins/installed.json", "inactive_for_profile") ||
		!hasNode(g, report.ComponentSkill, ".kimi-code/skills/flat.md", "") ||
		!hasNode(g, "agent", ".kimi-code/agents/review.md", "") ||
		!hasNode(g, "rule", ".kimi-code/AGENTS.md", "") || len(nodes(g, "handler")) != 0 {
		t.Fatalf("unexpected Kimi workspace: %+v", g)
	}
}
