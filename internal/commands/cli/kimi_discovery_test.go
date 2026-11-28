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

func TestKimiDiscoveryUsesRegistryAndSeparatesUserFromProject(t *testing.T) {
	home, kimi, project := t.TempDir(), t.TempDir(), t.TempDir()
	writeNativeFixture(t, home, ".kimi-code/mcp.json", `{"mcpServers":{"wrong-home":{"command":"printf"}}}`)
	writeNativeFixture(t, home, ".agents/skills/shared.md", "Shared skill.\n")
	writeNativeFixture(t, kimi, "AGENTS.md", "Personal instructions.\n")
	writeNativeFixture(t, kimi, "SYSTEM.md", "Personal system prompt.\n")
	writeNativeFixture(t, kimi, "config.toml", "[[hooks]]\nevent='SessionStart'\ncommand='printf ready'\n")
	writeNativeFixture(t, kimi, "credentials/demo.json", "{}")
	writeNativeFixture(t, kimi, "plugins/managed/unlisted/kimi.plugin.json", `{"name":"unlisted"}`)

	const managed = "plugins/managed/demo/"
	manifest := writeNativeFixture(t, kimi, managed+"kimi.plugin.json", `{"name":"demo","skills":"./recipes",
		"commands":"./prompts","systemPromptPath":"./SYSTEM.txt","mcpServers":{"local":{"command":"printf"}},
		"hooks":[{"event":"Stop","command":"printf done","timeout":30.0}]}`)
	writeNativeFixture(t, kimi, managed+".kimi-plugin/plugin.json", `{"name":"shadowed"}`)
	writeNativeFixture(t, kimi, managed+"prompts/review.md", "Review formatting.\n")
	writeNativeFixture(t, kimi, managed+"prompts/tools/review.md", "Review tooling.\n")
	writeNativeFixture(t, kimi, managed+"recipes/flat.md", "Format text.\n")
	writeNativeFixture(t, kimi, managed+"SYSTEM.txt", "Extension instructions.\n")

	const index = "plugins/installed.json"
	registry, err := json.Marshal(map[string]any{"version": 1, "plugins": []any{
		map[string]any{
			"id": "demo", "root": filepath.Dir(manifest), "source": "local-path", "enabled": false,
			"capabilities": map[string]any{"mcpServers": map[string]any{"local": map[string]bool{"enabled": false}}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeNativeFixture(t, kimi, index, string(registry))

	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, project, "AGENTS.md", "Shared project instructions.\n")
	writeNativeFixture(t, project, ".kimi-code/AGENTS.md", "Kimi project instructions.\n")
	writeNativeFixture(t, project, ".kimi-code/agents/check.md", "Review formatting.\n")
	writeNativeFixture(t, project, ".kimi-code/config.toml", "[[hooks]]\nevent='StopFailure'\ncommand='printf ignored'\n")
	writeNativeFixture(t, project, ".kimi-code/mcp.json", `{"mcpServers":{"workspace":{"url":"https://example.invalid/mcp"}}}`)

	args := []string{"discover", "--agent", report.HostKimiCode, "--home", home, "--kimi-home", kimi, "--project", project, "--system=false", "--format", "json"}
	code, raw := runCheckpoint(t, args)
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("invalid Kimi inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"user/skill/shared":                 "",
		"user/rule/AGENTS.md":               "",
		"user/rule/SYSTEM.md":               "",
		"user/hook/SessionStart":            "/hooks/0",
		"plugin/plugin/demo":                "",
		"plugin/command/tools/review":       "",
		"plugin/command/review":             "",
		"plugin/skill/flat":                 "",
		"plugin/rule/SYSTEM.txt":            "",
		"plugin/mcp-server/local":           "/mcpServers/local",
		"plugin/hook/Stop":                  "/hooks/0",
		"project/rule/.kimi-code/AGENTS.md": "",
		"project/rule/AGENTS.md":            "",
		"project/agent/check":               "",
		"project/mcp-server/workspace":      "/mcpServers/workspace",
	}
	for _, c := range inventory.Components {
		name := c.Name
		if c.Scope == "project" && strings.HasSuffix(filepath.ToSlash(c.Source), "/.kimi-code/AGENTS.md") {
			name = ".kimi-code/" + c.Name
		}
		key := c.Scope + "/" + c.Kind + "/" + name
		if expected, exists := want[key]; !exists || c.Key != expected || c.Agent != report.HostKimiCode ||
			c.Kind == "plugin" && c.State != "disabled" {
			t.Errorf("unexpected Kimi declaration: %+v", c)
		}
		delete(want, key)
	}
	if len(want) != 0 || len(inventory.Enablement) != 2 || !slices.ContainsFunc(inventory.Enablement, func(e discovery.Enablement) bool {
		return e.Key == "/plugins/0/capabilities/mcpServers/local/enabled" && e.State == "disabled"
	}) {
		t.Fatalf("missing declarations %v or registry settings %+v", want, inventory.Enablement)
	}
	if slices.ContainsFunc(inventory.Sources, func(source discovery.Source) bool {
		name := filepath.ToSlash(source.Path)
		return strings.Contains(name, "/credentials/") || strings.Contains(name, "/unlisted/") ||
			strings.HasSuffix(name, "/.kimi-plugin/plugin.json")
	}) {
		t.Fatalf("discovery opened data outside the registered declarations: %+v", inventory.Sources)
	}
}

func TestKimiPluginSnapshotComparesDeclaredAssets(t *testing.T) {
	home := t.TempDir()
	const (
		base  = ".kimi-code/plugins/managed/snapshot/"
		asset = "hooks/check.js"
	)
	manifest := writeNativeFixture(t, home, base+"kimi.plugin.json",
		`{"name":"snapshot","hooks":[{"event":"Stop","command":"node ./hooks/check.js"}]}`)
	entry, err := json.Marshal(map[string]any{"version": 1, "plugins": []any{
		map[string]any{"id": "snapshot", "root": filepath.Dir(manifest), "source": "local-path", "enabled": true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeNativeFixture(t, home, ".kimi-code/plugins/installed.json", string(entry))
	writeNativeFixture(t, home, base+asset, "console.log('before')\n")

	checkpoint := filepath.Join(t.TempDir(), "kimi.json")
	args := []string{
		"discover", "--agent", report.HostKimiCode, "--home", home, "--no-project", "--system=false",
		"--kind", "plugin", "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--scope", "selected",
	}
	if code, raw := runCheckpoint(t, args); code != 2 {
		t.Fatalf("unexpected snapshot exit %d: %s", code, raw)
	}

	writeNativeFixture(t, home, base+asset, "console.log('after')\n")
	code, raw := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--source-diff"))
	comparison := comparisonResult(t, raw)
	if code != 2 || comparison.Before == comparison.After || len(comparison.Roots) != 1 || comparison.Roots[0].Change != "modified" {
		t.Fatalf("comparison missed a Kimi plugin edit: exit %d: %+v", code, comparison.Roots)
	}

	content := comparison.Roots[0].Content
	if len(content) != 1 || content[0].Path != asset || content[0].AddedLines != 1 || content[0].RemovedLines != 1 {
		t.Fatalf("unexpected plugin source diff: %+v", content)
	}
	assertNativeGraph(t, comparison.Previous, report.HostKimiCode, "handler")
	assertNativeGraph(t, comparison.Current, report.HostKimiCode, "handler")
}

func TestKimiDiscoveryLeavesUnboundInstalledRootsUnresolved(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	external := writeNativeFixture(t, outside, "kimi.plugin.json", `{"name":"demo"}`)
	writeNativeFixture(t, home, ".kimi-code/plugins/managed/demo/kimi.plugin.json", `{"name":"demo"}`)
	registry, err := json.Marshal(map[string]any{
		"version": 1,
		"plugins": []any{
			map[string]any{"id": "demo", "root": filepath.Dir(external), "enabled": true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := writeNativeFixture(t, home, ".kimi-code/plugins/installed.json", string(registry))
	code, raw := runCheckpoint(t, []string{
		"discover", "--agent", report.HostKimiCode, "--home", home, "--no-project", "--system=false", "--format", "json",
	})
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 2 || inventory.Complete {
		t.Fatalf("expected partial inventory for external root, exit %d: %s", code, raw)
	}
	if len(inventory.Sources) != 1 || inventory.Sources[0].Path != index || len(inventory.Components) != 1 ||
		inventory.Components[0].Source != index || inventory.Components[0].Kind != "plugin" {
		t.Fatalf("external or stale managed bytes entered discovery: %+v", inventory)
	}
}
