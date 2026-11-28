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

func TestGeminiDiscoveryRelocatedHomeAndExtension(t *testing.T) {
	home, relocated := t.TempDir(), t.TempDir()
	writeNativeFixture(t, home, ".gemini/settings.json", `{"mcpServers":{"ignored":{"command":"printf"}}}`)
	discoverySkill(t, home, "ignored-alias", "Ignored.")
	discoverySkill(t, relocated, "chosen-alias", "Format text.")
	writeNativeFixture(t, relocated, ".gemini/settings.json", `{
		// User declarations are independent of package discovery.
		"mcpServers":{"example":{"url":"https://example.invalid/sse"}},
		"mcp":{"excluded":["example"]},
		"hooksConfig":{"enabled":false}
	}`)
	const extension = ".gemini/extensions/demo/"
	manifest := writeNativeFixture(t, relocated, extension+"gemini-extension.json", `{"name":"demo","version":"1.0.0","contextFileName":"docs/GUIDE.md"}`)
	writeNativeFixture(t, relocated, extension+"docs/GUIDE.md", "Format text.")
	writeNativeFixture(t, relocated, extension+"commands/team/format.toml", "prompt = 'Format text.'")
	writeNativeFixture(t, relocated, extension+"skills/format/SKILL.md", "Format text.")
	writeNativeFixture(t, relocated, extension+"hooks/hooks.json", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf sentinel-private"}]}]}}`)

	args := []string{"discover", "--agent", report.HostGeminiCLI, "--home", home, "--gemini-home", relocated, "--system=false", "--no-project"}
	code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete || strings.Contains(string(raw), "sentinel-private") {
		t.Fatalf("invalid Gemini inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"plugin/demo":         "plugin",
		"rule/GUIDE.md":       "plugin",
		"command/team:format": "plugin",
		"skill/format":        "plugin",
		"hook/SessionStart":   "plugin",
		"skill/chosen-alias":  "user",
		"mcp-server/example":  "user",
	}
	for _, c := range inventory.Components {
		key := c.Kind + "/" + c.Name
		if expected, ok := want[key]; !ok || c.Agent != report.HostGeminiCLI || c.Scope != expected {
			t.Fatalf("unexpected Gemini component: %+v", c)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing Gemini components: %v", want)
	}

	if !slices.Contains(inventory.Targets, filepath.Dir(manifest)) || len(inventory.Enablement) != 2 ||
		!slices.ContainsFunc(inventory.Enablement, func(e discovery.Enablement) bool {
			return e.Kind == "mcp-server" && e.Selector == "example" && e.State == "disabled" && e.Key == "/mcp/excluded/0"
		}) {
		t.Fatalf("unexpected extension target or enablement: %+v", inventory)
	}

	reportPath := filepath.Join(relocated, "inventory.json")
	if code, _ := runCheckpoint(t, append(slices.Clone(args), "--output", reportPath)); code != 0 {
		t.Fatal("relocated home did not allow a report outside agent inputs")
	}
	if code, _ := runCheckpoint(t, append(slices.Clone(args), "--output", manifest)); code != 2 {
		t.Fatal("extension manifest was not protected from report output")
	}
}
