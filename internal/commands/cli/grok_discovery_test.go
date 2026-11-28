package cli_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

func TestGrokDiscoveryReadsRelocatedHomeAndProject(t *testing.T) {
	home, relocated, project := t.TempDir(), t.TempDir(), t.TempDir()
	writeNativeFixture(t, home, ".grok/config.toml", "[mcp_servers.shadowed]\ncommand = 'printf'\n")
	writeNativeFixture(t, relocated, "config.toml", `
[plugins]
enabled = ["native"]
disabled = ["example"]
[[hooks.SessionStart]]
hooks = [{ type = "command", command = "printf user" }]
[mcp_servers.api]
url = "https://example.invalid/mcp"
bearer_token_file = "/some/private/token"
`)
	writeNativeFixture(t, relocated, "requirements.toml", "[[hooks.SessionEnd]]\nhooks = [{type = 'command', command = 'printf managed'}]\n")
	writeNativeFixture(t, relocated, "lsp.json", `{"format":{"command":"format-lsp"}}`)
	writeNativeFixture(t, relocated, "workflows/review.rhai", "fn run() { 1 }\n")
	writeNativeFixture(t, relocated, "workflows/ignored.md", "Not a Rhai workflow.\n")
	writeNativeFixture(t, relocated, "plugins/native/.grok-plugin/plugin.json", `{"name":"native","lspServers":"config/lsp.json"}`)
	writeNativeFixture(t, relocated, "plugins/native/config/lsp.json", `{"checks":{"command":"checks-lsp"}}`)
	writeNativeFixture(t, relocated, "plugins/native/hooks/hooks.json", `{"hooks":{"SubagentEnd":[{"hooks":[{"type":"http","url":"https://example.invalid/hook"}]}]}}`)
	writeNativeFixture(t, relocated, "plugins/example/.mcp.json", `{"demo":{"command":"printf"}}`)
	writeNativeFixture(t, relocated, "plugins/marketplaces/catalog/plugins/uninstalled/plugin.json", `{"name":"uninstalled"}`)
	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, project, ".grok/config.toml", "[[hooks.SessionStart]]\nhooks = [{type='command', command='printf project'}]\n")

	args := []string{"discover", "--home", home, "--grok-home", relocated, "--project", project, "--agent", report.HostGrokCLI, "--system=false"}
	code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("invalid Grok inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"user/hook/SessionStart":   "/hooks/SessionStart/0/hooks/0",
		"user/hook/SessionEnd":     "/hooks/SessionEnd/0/hooks/0",
		"user/mcp-server/api":      "/mcp_servers/api",
		"user/lsp-server/format":   "/format",
		"user/workflow/review":     "",
		"plugin/plugin/native":     "",
		"plugin/plugin/example":    "",
		"plugin/lsp-server/checks": "/checks",
		"plugin/hook/SubagentEnd":  "/hooks/SubagentEnd/0/hooks/0",
		"plugin/mcp-server/demo":   "/demo",
	}
	for _, c := range inventory.Components {
		key := c.Scope + "/" + c.Kind + "/" + c.Name
		if pointer, ok := want[key]; !ok || pointer != c.Key || c.Agent != report.HostGrokCLI {
			t.Fatalf("unexpected Grok declaration: %+v", c)
		}
		delete(want, key)
	}
	if len(want) != 0 || len(inventory.Enablement) != 2 {
		t.Fatalf("missing Grok declarations %v or enablement: %+v", want, inventory.Enablement)
	}

	code, raw = runCheckpoint(t, append(args, "--kind", "workflow", "--scan", "--", "--scope", "selected", "--profile", "custom", "--checks", "none", "--format", "json"))
	var scan report.Document
	if err := json.Unmarshal(raw, &scan); err != nil || scan.Validate() != nil || code != 2 {
		t.Fatalf("invalid Grok workflow scan, exit %d: %s", code, raw)
	}
	assertNativeGraph(t, &scan, report.HostGrokCLI, "workflow")
}
