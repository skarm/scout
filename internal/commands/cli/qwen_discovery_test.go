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

func TestQwenDiscoveryInventoriesContainedPackages(t *testing.T) {
	home, qwen, project := t.TempDir(), t.TempDir(), t.TempDir()
	writeNativeFixture(t, home, ".qwen/settings.json", `{"mcpServers":{"default-home":{"command":"printf"}}}`)
	writeNativeFixture(t, qwen, "settings.json", `{"disableAllHooks":true,"mcpServers":{"selected-home":{"command":"printf"}}}`)
	writeNativeFixture(t, qwen, ".env", "EXAMPLE_TOKEN=placeholder\n")
	writeNativeFixture(t, qwen, "hookApprovals.json", "{}")

	const ext = "extensions/native/"
	writeNativeFixture(t, qwen, ext+"qwen-extension.json", `{"name":"native","version":"1.0.0","hooks":"config/check.json",
		"lspServers":"config/lsp.json","commands":"prompts","channels":{"demo":{"entry":"dist/channel.js"}}}`)
	writeNativeFixture(t, qwen, ext+"QWEN.md", "Review changes.\n")
	writeNativeFixture(t, qwen, ext+"config/check.json", `{"Stop":[{"hooks":[{"type":"command","command":"printf done"}]}]}`)
	writeNativeFixture(t, qwen, ext+"config/lsp.json", `{"go":{"command":"gopls"}}`)
	writeNativeFixture(t, qwen, ext+"dist/channel.js", "export const plugin = {}\n")
	writeNativeFixture(t, qwen, ext+"prompts/fs/review.toml", "prompt = 'Review text.'\n")
	writeNativeFixture(t, qwen, ext+"hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf ignored"}]}]}}`)
	writeNativeFixture(t, qwen, "extensions/portable/plugin.json", `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"portable"}`)
	writeNativeFixture(t, qwen, "extensions/portable/mcp.json", `{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{
		"shared":{"type":"stdio","command":"printf"},"legacy":{"type":"sse","url":"https://example.invalid/sse"}}}`)
	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
	writeNativeFixture(t, project, "AGENTS.md", "Review formatting.\n")
	writeNativeFixture(t, project, ".mcp.json", `{"mcpServers":{"project":{"command":"printf"}}}`)
	writeNativeFixture(t, project, ".qwen/workflows/check.js", "export const meta = {name: 'check'}\n")
	writeNativeFixture(t, project, ".qwen/workflows/nested/ignored.js", "export const meta = {name: 'ignored'}\n")

	args := []string{"discover", "--agent", report.HostQwenCode, "--home", home, "--qwen-home", qwen, "--project", project, "--system=false", "--format", "json"}
	code, raw := runCheckpoint(t, args)
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("invalid Qwen inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"user/mcp-server/selected-home": "/mcpServers/selected-home",
		"plugin/plugin/native":          "",
		"plugin/hook/Stop":              "/Stop/0/hooks/0",
		"plugin/lsp-server/go":          "/go",
		"plugin/channel/demo":           "/channels/demo/entry",
		"plugin/rule/QWEN.md":           "",
		"plugin/command/fs:review":      "",
		"plugin/plugin/portable":        "",
		"plugin/mcp-server/shared":      "/mcpServers/shared",
		"project/rule/AGENTS.md":        "",
		"project/mcp-server/project":    "/mcpServers/project",
		"project/workflow/check":        "",
	}
	for _, c := range inventory.Components {
		key := c.Scope + "/" + c.Kind + "/" + c.Name
		if expected, exists := want[key]; !exists || c.Key != expected || c.Agent != report.HostQwenCode {
			t.Errorf("unexpected Qwen declaration: %+v", c)
		}

		delete(want, key)
	}

	if len(want) != 0 || len(inventory.Enablement) != 1 || inventory.Enablement[0].Key != "/disableAllHooks" || inventory.Enablement[0].State != "disabled" {
		t.Fatalf("missing declarations %v or local enablement: %+v", want, inventory.Enablement)
	}

	if slices.ContainsFunc(inventory.Sources, func(source discovery.Source) bool {
		name := filepath.ToSlash(source.Path)
		return slices.Contains([]string{".env", "hookApprovals.json", "ignored.js"}, filepath.Base(name)) ||
			strings.HasSuffix(name, "/hooks/hooks.json")
	}) {
		t.Errorf("discovery read unrelated data or an overridden hook file: %+v", inventory.Sources)
	}
}

func TestQwenExtensionSnapshotComparesDeclaredHookFile(t *testing.T) {
	home := t.TempDir()
	const (
		base = ".qwen/extensions/native/"
		hook = "config/check.json"
	)
	writeNativeFixture(t, home, base+"qwen-extension.json", `{"name":"native","version":"1.0.0","hooks":"config/check.json"}`)
	writeNativeFixture(t, home, base+hook, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf before"}]}]}}`)

	checkpoint := filepath.Join(t.TempDir(), "qwen.json")
	args := []string{
		"discover", "--agent", report.HostQwenCode, "--home", home, "--no-project", "--system=false",
		"--kind", "plugin", "--snapshot", checkpoint, "--", "--profile", "custom", "--checks", "none", "--scope", "selected",
	}
	if code, raw := runCheckpoint(t, args); code != 2 {
		t.Fatalf("unexpected snapshot exit %d: %s", code, raw)
	}

	writeNativeFixture(t, home, base+hook, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf after"}]}]}}`)
	code, raw := runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--source-diff"))
	comparison := comparisonResult(t, raw)
	if code != 2 || comparison.Before == comparison.After || len(comparison.Roots) != 1 || comparison.Roots[0].Change != "modified" {
		t.Fatalf("comparison missed the Qwen extension edit: exit %d: %+v", code, comparison.Roots)
	}

	content := comparison.Roots[0].Content
	if len(content) != 1 || content[0].Path != hook || content[0].AddedLines != 1 || content[0].RemovedLines != 1 {
		t.Fatalf("unexpected Qwen extension source diff: %+v", content)
	}

	assertNativeGraph(t, comparison.Previous, report.HostQwenCode, report.ComponentHook)
	assertNativeGraph(t, comparison.Current, report.HostQwenCode, report.ComponentHook)
}
