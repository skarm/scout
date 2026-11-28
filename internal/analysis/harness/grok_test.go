package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestGrokNativePackageAndCapturedHook(t *testing.T) {
	const (
		manifest = ".grok-plugin/plugin.json"
		hooks    = "config/lifecycle.json"
		handler  = "bin/check.sh"
	)
	g := inspect(t, map[string]string{
		manifest:      `{"name":"demo","hooks":"config/lifecycle.json","mcpServers":"config/mcp.json","agents":"custom/demo.md"}`,
		"plugin.json": `{"name":"compatible"}`,
		hooks: `{"hooks":{"StopCancelled":[{"hooks":[{"type":"command","command":"bash \"${GROK_PLUGIN_ROOT}/bin/check.sh\""},
			{"type":"command","command":"../bin/check.sh"},
			{"type":"http","url":"https://example.invalid/hook"}]}],
			"UnknownEvent":[{"hooks":[{"type":"command","command":"printf ignore"}]}]}}`,
		handler:           "printf 'checked\\n'\n",
		"custom/demo.md":  "Review the formatting.\n",
		".lsp.json":       `{"example":{"command":"example-lsp","extensionToLanguage":{".demo":"demo"}}}`,
		"config/mcp.json": `{"example":{"command":"printf","args":["ready"],"enabled":false}}`,
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostGrokCLI || !slices.Equal(g.Plugins[0].Manifests, []string{manifest}) {
		t.Fatalf("wrong Grok package interpretation: %+v", g.Plugins)
	}

	invocations := 0
	for _, edge := range g.Edges {
		if edge.Relation == "invokes" {
			invocations++
		}
	}

	if len(nodes(g, report.ComponentHook)) != 3 || invocations != 2 || !hasNode(g, "agent", "custom/demo.md", "") ||
		!hasNode(g, "handler", handler, "") || !hasNode(g, "lsp_server", ".lsp.json", "") ||
		!hasNode(g, "mcp_server", "config/mcp.json", "inactive_for_profile") ||
		!hasReference(g, report.ReferenceUnresolved, "remote_behavior_unverified") {
		t.Fatalf("unexpected Grok package components or references: %+v %+v", g.Components, g.References)
	}
}

func TestGrokCatalogAndManifestlessPackageStayDistinct(t *testing.T) {
	const (
		catalog = ".grok/plugins/marketplaces/example/.grok-plugin/plugin.json"
		mcp     = ".grok/plugins/local/.mcp.json"
		hook    = ".grok/hooks/check.json"
	)
	g := inspect(t, map[string]string{
		catalog:                      `{"name":"example","plugins":[{"name":"catalog-only","source":"https://example.invalid/repo"}]}`,
		mcp:                          `{"example":{"command":"printf","args":["ready"]}}`,
		hook:                         `{"StopCancelled":[{"hooks":[{"type":"command","command":"bash \"${GROK_PLUGIN_ROOT}/bin/check.sh\""}]}]}`,
		".grok/workflows/check.rhai": "fn run() { 1 }\n",
		"bin/check.sh":               "printf 'checked\\n'\n",
	}, report.HostAuto)

	if len(g.Plugins) != 2 || !hasNode(g, "marketplace", catalog, "") || !hasNode(g, "mcp_server", mcp, "") ||
		!hasNode(g, report.ComponentHook, hook, "") || !hasNode(g, "workflow", ".grok/workflows/check.rhai", "") ||
		len(nodes(g, "handler")) != 0 {
		t.Fatalf("unexpected Grok catalog, package, or workspace: %+v %+v", g.Plugins, g.Components)
	}
}

func TestGrokMalformedTOMLDoesNotCreateServer(t *testing.T) {
	const config = ".grok/config.toml"
	g := inspect(t, map[string]string{
		config: "[mcp_servers.example]\nurl = 'https://example.invalid/first'\nurl = 'https://example.invalid/second'\n",
	}, report.HostAuto)
	if len(g.Plugins) != 1 || g.Plugins[0].FormatStatus != "invalid" || len(nodes(g, "mcp_server")) != 0 ||
		!slices.ContainsFunc(g.Issues, func(issue report.HarnessIssue) bool {
			return issue.Code == "plugin_toml_invalid" && issue.Path == config
		}) {
		t.Fatalf("malformed Grok TOML was accepted or mislabeled: %+v", g)
	}
}
