package cli_test

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

func TestZCodeDiscoveryInventoriesContainedPackagesAndScopedMCP(t *testing.T) {
	home, relocated, project := t.TempDir(), t.TempDir(), t.TempDir()
	writeNativeFixture(t, home, ".agents/mcp.json", `{"mcpServers":{"user-fallback":{"type":"stdio","command":"printf"}}}`)
	writeNativeFixture(t, home, ".zcode/cli/config.json", `{"mcp":{"servers":{"stale":{"type":"stdio","command":"printf"}}}}`)
	writeNativeFixture(t, relocated, "cli/config.json", `{"plugins":{"enabledPlugins":{"native@fixture":false}}}`)
	writeNativeFixture(t, relocated, "cli/plugins/installed_plugins.json", `{"plugins":[{"id":"native@fixture","name":"native","installPath":"/outside/cache"}]}`)
	writeNativeFixture(t, relocated, "cli/plugins/cache/fixture/native/1.0.0/.zcode-plugin/plugin.json", `{"name":"native"}`)
	writeNativeFixture(t, relocated, "cli/plugins/cache/fixture/native/1.0.0/hooks/hooks.json", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf ready"}]}]}}`)
	writeNativeFixture(t, relocated, "cli/plugins/marketplaces/fixture/source/.zcode-plugin/plugin.json", `{"name":"uninstalled"}`)
	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, project, "AGENTS.md", "Review formatting.\n")
	writeNativeFixture(t, project, ".agents/mcp.json", `{"mcpServers":{"project-shadowed":{"type":"stdio","command":"printf"}}}`)
	writeNativeFixture(t, project, ".zcode/config.json", `{
		"mcp":{"servers":{"project-native":{"type":"http","url":"https://example.invalid/mcp","enabled":false}}},
		"plugins":{"dirs":["tools/local"]}
	}`)
	writeNativeFixture(t, project, "tools/local/.claude-plugin/plugin.json", `{"name":"compatible","mcpServers":{"local-tool":{"command":"printf"}}}`)
	writeNativeFixture(t, project, ".zcode/skills/format/SKILL.md", "---\nname: format\ndescription: Format text.\n---\n")
	writeNativeFixture(t, project, ".zcode/agents/reviewer.md", "Review content.\n")
	writeNativeFixture(t, project, ".zcode/commands/format.md", "Format text.\n")

	args := []string{"discover", "--agent", report.HostZCode, "--home", home, "--zcode-home", relocated, "--project", project, "--system=false", "--format", "json"}
	code, raw := runCheckpoint(t, args)
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("invalid ZCode inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"user/mcp-server/user-fallback":     "/mcpServers/user-fallback",
		"user/plugin/native@fixture":        "/plugins/0",
		"plugin/plugin/native":              "",
		"plugin/hook/SessionStart":          "/hooks/SessionStart/0/hooks/0",
		"project/mcp-server/project-native": "/mcp/servers/project-native",
		"project/rule/AGENTS.md":            "",
		"project/skill/format":              "",
		"project/agent/reviewer":            "",
		"project/command/format":            "",
		"plugin/plugin/compatible":          "",
		"plugin/mcp-server/local-tool":      "/mcpServers/local-tool",
	}
	for _, c := range inventory.Components {
		key := c.Scope + "/" + c.Kind + "/" + c.Name
		if expected, ok := want[key]; !ok || c.Key != expected || c.Agent != report.HostZCode {
			t.Fatalf("unexpected ZCode declaration %+v", c)
		}
		delete(want, key)
	}

	if len(want) != 0 || len(inventory.Enablement) != 1 || inventory.Enablement[0].State != "disabled" {
		t.Fatalf("missing declarations %v or enablement: %+v", want, inventory.Enablement)
	}

	if slices.ContainsFunc(inventory.Sources, func(source discovery.Source) bool {
		name := filepath.ToSlash(source.Path)
		return strings.Contains(name, "/marketplaces/") || strings.HasPrefix(name, "/outside/")
	}) {
		t.Fatalf("ZCode followed a catalogue or installation path: %+v", inventory.Sources)
	}
}
