package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestZCodePackageUsesNativeManifestAndLinksCapturedProcesses(t *testing.T) {
	const (
		manifest = ".zcode-plugin/plugin.json"
		hooks    = "hooks/hooks.json"
		custom   = "config/extra.json"
		handler  = "scripts/check.mjs"
	)
	g := inspect(t, map[string]string{
		manifest:                     `{"name":"native","hooks":["config/extra.json"],"commands":"custom/review.md"}`,
		".claude-plugin/plugin.json": `{"name":"legacy","mcpServers":{"ignored":{"command":"printf"}}}`,
		hooks:                        `{"hooks":{"SessionStart":[{"hooks":[{"type":"process","command":"node","args":["${ZCODE_PLUGIN_ROOT}/scripts/check.mjs"]}]}]}}`,
		custom:                       `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf finished","enabled":false}]}]}}`,
		".mcp.json":                  `{"mcpServers":{"local":{"type":"stdio","command":"node","args":["${ZCODE_PLUGIN_ROOT}/scripts/check.mjs"]}}}`,
		handler:                      "console.log('ready')\n",
		"custom/review.md":           "Review the formatting.\n",
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostZCode || !slices.Equal(g.Plugins[0].Manifests, []string{manifest}) {
		t.Fatalf("unexpected ZCode manifest precedence: %+v", g.Plugins)
	}

	invocations := 0
	for _, edge := range g.Edges {
		if edge.Relation == "invokes" {
			invocations++
		}
	}
	if invocations != 2 || len(nodes(g, "mcp_server")) != 1 || len(nodes(g, report.ComponentHook)) != 2 ||
		!hasNode(g, report.ComponentHook, custom, "inactive_for_profile") || !hasNode(g, "handler", handler, "") ||
		!hasNode(g, "command", "custom/review.md", "") {
		t.Fatalf("missing package declarations or captured links: %+v", g)
	}
}

func TestZCodeWorkspaceShadowsSharedMCPAndKeepsProcessBoundaries(t *testing.T) {
	const native = ".zcode/config.json"
	g := inspect(t, map[string]string{
		native: `{"mcp":{"servers":{"native":{"type":"http","url":"https://example.invalid/mcp"}}},
			"hooks":{"events":{"Stop":[{"hooks":[{"type":"process","command":"node ${ZCODE_PLUGIN_ROOT}/guard.mjs","args":[]}]}]}}}`,
		".agents/mcp.json": `{"mcpServers":{"compat":{"command":"printf"}}}`,
		"guard.mjs":        "console.log('ready')\n",
	}, report.HostAuto)

	if !hasNode(g, "mcp_server", native, "") ||
		!hasNode(g, "mcp_server", ".agents/mcp.json", "inactive_for_profile") ||
		!hasNode(g, report.ComponentHook, native, "") || len(nodes(g, "handler")) != 0 {
		t.Fatalf("wrong workspace scope or process interpretation: %+v", g)
	}
}

func TestZCodeInvalidNativeEntryDoesNotShadowSharedMCP(t *testing.T) {
	g := inspect(t, map[string]string{
		".zcode/config.json": `{"mcp":{"servers":{"invalid":null}}}`,
		".agents/mcp.json":   `{"mcpServers":{"shared":{"type":"stdio","command":"printf"}}}`,
	}, report.HostZCode)

	if !hasNode(g, "mcp_server", ".agents/mcp.json", "conditional") {
		t.Fatalf("invalid native config hid the shared declaration: %+v", g)
	}
}

func TestZCodeScansRelocatedHomeDirectory(t *testing.T) {
	g := inspect(t, map[string]string{
		"cli/config.json":      `{"mcp":{"servers":{"demo":{"type":"stdio","command":"printf"}}}}`,
		"skills/demo/SKILL.md": "Demo instructions.\n",
		"commands/demo.md":     "Demo command.\n",
	}, report.HostZCode)

	if !hasNode(g, "mcp_server", "cli/config.json", "") ||
		!hasNode(g, report.ComponentSkill, "skills/demo/SKILL.md", "conditional") ||
		!hasNode(g, "command", "commands/demo.md", "") {
		t.Fatalf("could not interpret a relocated ZCode home: %+v", g)
	}
}

func TestZCodeMarketplaceDoesNotMaterializePackages(t *testing.T) {
	const name = ".zcode-plugin/marketplace.json"
	g := inspect(t, map[string]string{
		name: `{"name":"fixture","plugins":[{"name":"example","source":"./plugins/example"}]}`,
	}, report.HostAuto)

	catalogs := nodes(g, "marketplace")
	if len(g.Plugins) != 0 || len(catalogs) != 1 || catalogs[0].Host != report.HostZCode || catalogs[0].Path != name {
		t.Fatalf("marketplace was not kept as a catalogue: %+v", g)
	}
}
