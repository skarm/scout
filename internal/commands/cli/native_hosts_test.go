package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/report"
)

func TestNativeDiscoveryScanAndSnapshot(t *testing.T) {
	tests := []struct {
		host, config, initial, updated string
		kind, name, key, state         string
		userConfig                     bool
	}{
		{
			host: report.HostCursor, config: ".cursor/hooks.json",
			initial: `{"version":1,"hooks":{"beforeShellExecution":[{"command":"printf hello"}]}}`,
			updated: `{"version":1,"hooks":{"beforeShellExecution":[{"command":"printf updated"}]}}`,
			kind:    "hook", name: "beforeShellExecution", key: "/hooks/beforeShellExecution/0", state: "unknown",
		},
		{
			host: report.HostCopilotCLI, config: ".github/hooks/check.json",
			initial: `{"version":1,"hooks":{"preToolUse":[{"type":"command","exec":"printf","args":["hello"]}]}}`,
			updated: `{"version":1,"hooks":{"preToolUse":[{"type":"command","exec":"printf","args":["updated"]}]}}`,
			kind:    "hook", name: "preToolUse", key: "/hooks/preToolUse/0", state: "unknown",
		},
		{
			host: report.HostGeminiCLI, config: ".gemini/settings.json",
			initial: `{// Gemini accepts comments in settings.json
				"mcpServers":{"example":{"httpUrl":"https://example.invalid/old"}}
			}`,
			updated: `{// Gemini accepts comments in settings.json
				"mcpServers":{"example":{"httpUrl":"https://example.invalid/new"}}
			}`,
			kind: "mcp-server", name: "example", key: "/mcpServers/example", state: "unknown",
		},
		{
			host: report.HostOpenClaw, config: ".openclaw/openclaw.json", userConfig: true,
			initial: `{// OpenClaw JSON5
				mcp: { servers: { example: { url: 'https://example.invalid/old', enabled: false, }, }, },
			}`,
			updated: `{// OpenClaw JSON5
				mcp: { servers: { example: { url: 'https://example.invalid/new', enabled: false, }, }, },
			}`,
			kind: "mcp-server", name: "example", key: "/mcp/servers/example", state: "disabled",
		},
		{
			host: report.HostOpenCode, config: "opencode.jsonc",
			initial: `{// example
				"mcp":{"servers":{"example":{"type":"remote","url":"https://example.invalid/old","disabled":true},},},
			}`,
			updated: `{// example
				"mcp":{"servers":{"example":{"type":"remote","url":"https://example.invalid/new","disabled":true},},},
			}`,
			kind: "mcp-server", name: "example", key: "/mcp/servers/example", state: "disabled",
		},
		{
			host: report.HostGrokCLI, config: ".grok/config.toml",
			initial: "[mcp_servers.example]\nurl = \"https://example.invalid/old\"\nenabled = false\n",
			updated: "[mcp_servers.example]\nurl = \"https://example.invalid/new\"\nenabled = false\n",
			kind:    "mcp-server", name: "example", key: "/mcp_servers/example", state: "disabled",
		},
		{
			host: report.HostGrokCLI, config: ".grok/hooks/cancel.json",
			initial: `{"hooks":{"StopCancelled":[{"hooks":[{"type":"command","command":"printf hello"}]}]}}`,
			updated: `{"hooks":{"StopCancelled":[{"hooks":[{"type":"command","command":"printf updated"}]}]}}`,
			kind:    "hook", name: "StopCancelled", key: "/hooks/StopCancelled/0/hooks/0", state: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			project, home := t.TempDir(), t.TempDir()
			writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")
			root, scope := project, "project"
			if tt.userConfig {
				root, scope = home, "user"
			}
			file := writeNativeFixture(t, root, tt.config, tt.initial)
			args := []string{"discover", "--home", home, "--project", project, "--agent", tt.host, "--system=false", "--kind", tt.kind}

			code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
			var inventory discovery.Snapshot
			if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete || len(inventory.Components) != 1 || !slices.Equal(inventory.Targets, []string{file}) {
				t.Fatalf("invalid inventory, exit %d: %s", code, raw)
			}
			c := inventory.Components[0]
			if c.Agent != tt.host || c.Scope != scope || c.Source != file || c.Kind != tt.kind || c.Name != tt.name || c.Key != tt.key || c.State != tt.state {
				t.Fatalf("unexpected declaration: %+v", c)
			}

			flags := []string{"--", "--profile", "custom", "--checks", "none", "--format", "json", "--scope", "selected"}
			scanArgs := append(append(slices.Clone(args), "--scan"), flags...)
			code, raw = runCheckpoint(t, scanArgs)
			var scan report.Document
			// A local declaration can be captured without verifying a host's runtime.
			if err := json.Unmarshal(raw, &scan); err != nil || scan.Validate() != nil || code != 2 || len(scan.Run.Targets) != 1 {
				t.Fatalf("invalid scan, exit %d, state %s, problems %+v", code, scan.Run.State, scan.Run.Problems)
			}
			kind := report.ComponentHook
			if tt.kind == "mcp-server" {
				kind = "mcp_server"
			}
			assertNativeGraph(t, &scan, tt.host, kind)

			checkpoint := filepath.Join(t.TempDir(), "before.json")
			if code, _ := runCheckpoint(t, append(append(slices.Clone(args), "--snapshot", checkpoint), flags...)); code != 2 {
				t.Fatalf("snapshot creation exited %d", code)
			}
			code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected"))
			comparison := comparisonResult(t, raw)
			if code != 2 || comparison.Before != comparison.After || len(comparison.Roots) != 1 || comparison.Roots[0].Change != "unchanged" {
				t.Fatalf("unchanged comparison exited %d: %+v", code, comparison.Roots)
			}

			writeNativeFixture(t, root, tt.config, tt.updated)
			candidate := filepath.Join(t.TempDir(), "after.json")
			code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--source-diff", "--save-candidate", candidate))
			comparison = comparisonResult(t, raw)
			if code != 2 || comparison.Before == comparison.After || len(comparison.Roots) != 1 || comparison.Roots[0].Change != "modified" {
				t.Fatalf("comparison missed a native config edit: exit %d: %+v", code, comparison.Roots)
			}
			content := comparison.Roots[0].Content
			if len(content) != 1 || content[0].Path != filepath.Base(file) || content[0].AddedLines != 1 || content[0].RemovedLines != 1 {
				t.Fatalf("unexpected source diff: %+v", content)
			}
			assertNativeGraph(t, comparison.Previous, tt.host, kind)
			assertNativeGraph(t, comparison.Current, tt.host, kind)

			code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--candidate", candidate))
			archived := comparisonResult(t, raw)
			if code != 2 || archived.Before != comparison.Before || archived.After != comparison.After || len(archived.Roots) != 1 || archived.Roots[0].Change != "modified" {
				t.Fatalf("archived comparison differs from discovery replay: exit %d: %+v", code, archived.Roots)
			}

			assertNativeGraph(t, archived.Previous, tt.host, kind)
			assertNativeGraph(t, archived.Current, tt.host, kind)
		})
	}
}

func assertNativeGraph(t *testing.T, doc *report.Document, host, kind string) {
	t.Helper()
	if doc == nil || len(doc.Run.Targets) != 1 {
		t.Fatal("missing native scan")
	}

	graph := doc.Run.Targets[0].Analysis.Components
	if graph.RequestedHost != host || !slices.ContainsFunc(graph.Components, func(c report.Component) bool {
		return c.Host == host && c.Kind == kind && c.Source != nil
	}) {
		t.Fatalf("missing %s %s declaration: %+v", host, kind, graph)
	}
}

func writeNativeFixture(t *testing.T, root, name, data string) string {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(file)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestNativeInstalledPluginsAndSharedSkills(t *testing.T) {
	home := t.TempDir()
	discoverySkill(t, home, "shared", "Format text.")
	cursor := ".cursor/plugins/local/cursor-demo/"
	writeNativeFixture(t, home, cursor+".cursor-plugin/plugin.json", `{"name":"cursor-demo","rules":"rules/review.mdc","mcpServers":"config/servers.json"}`)
	writeNativeFixture(t, home, cursor+"rules/review.mdc", "Review formatting.")
	writeNativeFixture(t, home, cursor+"mcp.json", `{"mcpServers":{"ignored":{"command":"echo"}}}`)
	writeNativeFixture(t, home, cursor+"config/servers.json", `{"mcpServers":{"cursor-mcp":{"command":"echo"}}}`)
	copilot := ".copilot/installed-plugins/demo/"
	writeNativeFixture(t, home, copilot+".plugin/plugin.json", `{"name":"copilot-demo"}`)
	writeNativeFixture(t, home, copilot+"plugin.json", `{"name":"ignored-legacy"}`)
	writeNativeFixture(t, home, copilot+".mcp.json", `{"copilot-mcp":{"type":"local","command":"echo"}}`)
	writeNativeFixture(t, home, ".copilot/hooks/user.json", `{"version":1,"hooks":{"sessionEnd":[{"command":"printf done"}]}}`)
	writeNativeFixture(t, home, ".copilot/settings.json", `{"hooks":{"sessionStart":[{"command":"printf start"}]}}`)
	opencode := ".config/opencode/"
	writeNativeFixture(t, home, opencode+"opencode.json", `{"mcp":{"legacy":{"enabled":false}}}`)
	writeNativeFixture(t, home, opencode+"plugins/example/index.ts", "export default async () => ({})\n")
	writeNativeFixture(t, home, opencode+"tools/helper.ts", "export default {}\n")

	code, raw := runCheckpoint(t, []string{"discover", "--home", home, "--no-project", "--system=false", "--format", "json"})
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("invalid installed inventory, exit %d: %s", code, raw)
	}

	want := map[string]string{
		"cursor/plugin/cursor-demo":          "unknown",
		"cursor/mcp-server/cursor-mcp":       "unknown",
		"copilot-cli/plugin/copilot-demo":    "unknown",
		"copilot-cli/mcp-server/copilot-mcp": "unknown",
		"copilot-cli/hook/sessionEnd":        "unknown",
		"copilot-cli/hook/sessionStart":      "unknown",
		"opencode/mcp-server/legacy":         "disabled",
		"opencode/plugin/example":            "unknown",
		"opencode/tool/helper.ts":            "unknown",
		"codex/skill/shared":                 "unknown",
		"cursor/skill/shared":                "unknown",
		"opencode/skill/shared":              "unknown",
		"gemini-cli/skill/shared":            "unknown",
		"openclaw/skill/shared":              "unknown",
		"grok-cli/skill/shared":              "unknown",
	}
	sharedTargets := 0
	for _, target := range inventory.Targets {
		if strings.HasSuffix(target, filepath.Join(".agents", "skills")) {
			sharedTargets++
		}
	}
	if sharedTargets != 1 {
		t.Fatalf("shared skill did not compact to one target: %v", inventory.Targets)
	}
	for _, c := range inventory.Components {
		key := c.Agent + "/" + c.Kind + "/" + c.Name
		if expected, ok := want[key]; ok {
			if c.State != expected {
				t.Fatalf("%s: want state %q, got %+v", key, expected, c)
			}
			delete(want, key)
		}
		if c.Name == "ignored" || c.Name == "ignored-legacy" {
			t.Fatalf("shadowed declaration loaded: %+v", c)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing installed declarations: %v", want)
	}
}
