package harness_test

import (
	"testing"

	"github.com/skarm/scout/report"
)

func TestNativeCursorInterpretsCustomPathsAndFlatHooks(t *testing.T) {
	const (
		manifest = ".cursor-plugin/plugin.json"
		hooks    = "config/hooks.json"
		handler  = "bin/format.sh"
	)
	g := inspect(t, map[string]string{
		manifest:              `{"name":"demo","rules":"rules/review.mdc","commands":"commands/format.txt","hooks":"config/hooks.json","mcpServers":"config/mcp.json"}`,
		hooks:                 `{"version":1,"hooks":{"beforeShellExecution":[{"command":"./bin/format.sh"}]}}`,
		handler:               "printf 'formatted\\n'\n",
		"rules/review.mdc":    "---\nalwaysApply: true\n---\nReview formatting.\n",
		"commands/format.txt": "Format plain text.\n",
		"config/mcp.json":     `{"mcpServers":{"example":{"command":"${CURSOR_PLUGIN_ROOT}/bin/format.sh"}}}`,
		"mcp.json":            `{"mcpServers":{"fallback":{"command":"echo"}}}`,
	}, report.HostCursor)
	if len(g.Plugins) != 1 || len(g.Plugins[0].Manifests) != 1 || g.Plugins[0].Manifests[0] != manifest {
		t.Fatalf("native package was duplicated or misidentified: %+v", g.Plugins)
	}
	if !hasNode(g, "rule", "rules/review.mdc", "") || !hasNode(g, "command", "commands/format.txt", "") ||
		!hasNode(g, report.ComponentHook, hooks, "") || !hasNode(g, "handler", handler, "") ||
		!hasNode(g, "mcp_server", "mcp.json", "inactive_for_profile") || !hasNode(g, "mcp_server", "config/mcp.json", "") {
		t.Fatalf("unexpected component graph: %+v", g.Components)
	}
}

func TestNativeCopilotManifestPriorityAndArgv(t *testing.T) {
	const manifest = ".plugin/plugin.json"
	g := inspect(t, map[string]string{
		manifest:                     `{"name":"preferred","hooks":"config/hooks.json"}`,
		"plugin.json":                `{"name":"legacy-root"}`,
		".github/plugin/plugin.json": `{"name":"legacy-github"}`,
		".claude-plugin/plugin.json": `{"name":"legacy-claude"}`,
		"config/hooks.json":          `{"version":1,"hooks":{"preToolUse":[{"type":"command","exec":"./verify.sh","args":["value with spaces"],"cwd":"./scripts"}]}}`,
		"scripts/verify.sh":          "printf '%s\\n' \"$1\"\n",
		".mcp.json":                  `{"$schema":"https://example.invalid/mcp.json","local":{"type":"local","command":"echo"}}`,
	}, report.HostCopilotCLI)
	if len(g.Plugins) != 1 || len(g.Plugins[0].Manifests) != 1 || g.Plugins[0].Manifests[0] != manifest {
		t.Fatalf("wrong plugin manifest precedence: %+v", g.Plugins)
	}
	if !hasNode(g, report.ComponentHook, "config/hooks.json", "") || !hasNode(g, "handler", "scripts/verify.sh", "") ||
		len(nodes(g, "mcp_server")) != 1 || !hasNode(g, "mcp_server", ".mcp.json", "") {
		t.Fatalf("missing Copilot declarations or handler: %+v", g.Components)
	}
}

func TestNativeOpenCodeJSONCPluginAndMCPSource(t *testing.T) {
	const config = "opencode.jsonc"
	files := map[string]string{
		config: `{
			// The handler is declared relative to the captured workspace.
			"mcp": {"servers": {
				"local": {"type":"local","command":["node","./bin/server.js"],},
				"paused": {"type":"remote","url":"https://example.invalid/mcp","disabled":true},
			},},
			"plugins": [{"package":"./packages/demo","options":{}}, "demo-package", "-paused-plugin",],
		}`,
		"bin/server.js":              "export default {}\n",
		"packages/demo/package.json": `{"exports":{"./server":"./entry.js"}}`,
		"packages/demo/entry.js":     "export default {}\n",
		".opencode/plugins/auto.ts":  "export default async () => ({})\n",
		".opencode/tools/helper.ts":  "export default {}\n",
	}
	g := inspect(t, files, report.HostAuto)
	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostOpenCode ||
		len(nodes(g, "mcp_server")) != 2 || !hasNode(g, "mcp_server", config, "inactive_for_profile") ||
		!hasNode(g, "handler", "bin/server.js", "") || !hasNode(g, "handler", "packages/demo/entry.js", "") ||
		!hasNode(g, "extension", ".opencode/plugins/auto.ts", "") || !hasNode(g, "tool", ".opencode/tools/helper.ts", "") ||
		!hasReference(g, report.ReferenceUnresolved, "external_dependency_not_materialized") {
		t.Fatalf("unexpected OpenCode interpretation: %+v", g)
	}
}
