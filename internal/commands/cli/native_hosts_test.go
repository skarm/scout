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

type nativeFixture struct {
	host, config, initial, updated string
	kind, name, key, state         string
	userConfig                     bool
}

func nativeFixtures() []nativeFixture {
	return []nativeFixture{
		{
			host: report.HostCodex, config: ".codex/config.toml", userConfig: true,
			initial: "[mcp_servers.example]\nurl = \"https://example.invalid/old\"\nenabled = false\n",
			updated: "[mcp_servers.example]\nurl = \"https://example.invalid/new\"\nenabled = false\n",
			kind:    "mcp-server", name: "example", key: "/mcp_servers/example", state: "disabled",
		},
		{
			host: report.HostClaudeCode, config: ".claude/settings.local.json",
			initial: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf before"}]}]}}`,
			updated: `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf after"}]}]}}`,
			kind:    "hook", name: "SessionStart", key: "/hooks/SessionStart/0/hooks/0", state: "unknown",
		},
		{
			host: report.HostClaudeCode, config: ".claude.json", userConfig: true,
			initial: `{"mcpServers":{"example":{"type":"http","url":"https://example.invalid/old"}}}`,
			updated: `{"mcpServers":{"example":{"type":"http","url":"https://example.invalid/new"}}}`,
			kind:    "mcp-server", name: "example", key: "/mcpServers/example", state: "unknown",
		},
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
			host: report.HostCopilotCLI, config: ".github/mcp.json",
			initial: `{"example":{"type":"http","url":"https://example.invalid/old"}}`,
			updated: `{"example":{"type":"http","url":"https://example.invalid/new"}}`,
			kind:    "mcp-server", name: "example", key: "/example", state: "unknown",
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
		{
			host: report.HostDeepSeekHarness, config: ".dsh/profiles/web/cordis.patch.yml", userConfig: true,
			initial: "- insert:\n    - name: '@deepseek-ai/dsh-mcp-manager/server'\n      disabled: true\n      config:\n        serverName: example\n        transport: streamable-http\n        url: https://example.invalid/old\n",
			updated: "- insert:\n    - name: '@deepseek-ai/dsh-mcp-manager/server'\n      disabled: true\n      config:\n        serverName: example\n        transport: streamable-http\n        url: https://example.invalid/new\n",
			kind:    "mcp-server", name: "example", key: "/0/insert/0/config", state: "disabled",
		},
		{
			host: report.HostZCode, config: ".zcode/config.json",
			initial: `{"mcp":{"servers":{"example":{"type":"http","url":"https://example.invalid/old","enabled":false}}}}`,
			updated: `{"mcp":{"servers":{"example":{"type":"http","url":"https://example.invalid/new","enabled":false}}}}`,
			kind:    "mcp-server", name: "example", key: "/mcp/servers/example", state: "disabled",
		},
		{
			host: report.HostZCode, config: "zcode.json",
			initial: `{"hooks":{"enabled":true,"events":{"Stop":[{"hooks":[{"type":"process","command":"printf","args":["before"]}]}]}}}`,
			updated: `{"hooks":{"enabled":true,"events":{"Stop":[{"hooks":[{"type":"process","command":"printf","args":["after"]}]}]}}}`,
			kind:    "hook", name: "Stop", key: "/hooks/events/Stop/0/hooks/0", state: "unknown",
		},
		{
			host: report.HostQwenCode, config: ".qwen/settings.json", userConfig: true,
			initial: "\ufeff" + `{// Personal Qwen settings.
				"mcpServers":{"example":{"httpUrl":"https://example.invalid/old"}}
			}`,
			updated: "\ufeff" + `{// Personal Qwen settings.
				"mcpServers":{"example":{"httpUrl":"https://example.invalid/new"}}
			}`,
			kind: "mcp-server", name: "example", key: "/mcpServers/example", state: "unknown",
		},
		{
			host: report.HostQwenCode, config: ".qwen/settings.json",
			initial: `{"hooks":{"InstructionsLoaded":[{"hooks":[{"type":"command","command":"printf before"}]}]}}`,
			updated: `{"hooks":{"InstructionsLoaded":[{"hooks":[{"type":"command","command":"printf after"}]}]}}`,
			kind:    "hook", name: "InstructionsLoaded", key: "/hooks/InstructionsLoaded/0/hooks/0", state: "unknown",
		},
		{
			host: report.HostKimiCode, config: ".kimi-code/config.toml", userConfig: true,
			initial: "[[hooks]]\nevent = \"SessionHeartbeat\"\ncommand = \"printf before\"\n",
			updated: "[[hooks]]\nevent = \"SessionHeartbeat\"\ncommand = \"printf after\"\n",
			kind:    "hook", name: "SessionHeartbeat", key: "/hooks/0", state: "unknown",
		},
		{
			host: report.HostKimiCode, config: ".kimi-code/mcp.json",
			initial: `{"mcpServers":{"example":{"transport":"sse","url":"https://example.invalid/old","enabled":false}}}`,
			updated: `{"mcpServers":{"example":{"transport":"sse","url":"https://example.invalid/new","enabled":false}}}`,
			kind:    "mcp-server", name: "example", key: "/mcpServers/example", state: "disabled",
		},
	}
}

func TestNativeDiscoveryScanAndSnapshot(t *testing.T) {
	covered := make(map[string]bool)
	for _, tt := range nativeFixtures() {
		covered[tt.host] = true
		t.Run(tt.host+"/"+tt.config, func(t *testing.T) {
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

			direct := append([]string{"scan", "--harness", tt.host}, flags[1:]...)
			code, raw = runCheckpoint(t, append(direct, file))
			var directScan report.Document
			if err := json.Unmarshal(raw, &directScan); err != nil || directScan.Validate() != nil || code != 2 {
				t.Fatalf("invalid direct scan, exit %d: %s", code, raw)
			}
			assertNativeGraph(t, &directScan, tt.host, kind)

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

			if tt.host == report.HostCodex || tt.config == ".claude/settings.local.json" {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected"))
				removed := comparisonResult(t, raw)
				if code != 2 || len(removed.Roots) != 1 || removed.Roots[0].Change != "removed" {
					t.Fatalf("removed native config was not reported: exit %d: %+v", code, removed.Roots)
				}
				assertNativeGraph(t, removed.Previous, tt.host, kind)
			}
		})
	}

	for _, agent := range discovery.AgentSelectors() {
		if agent != discovery.AllAgents && !covered[agent] {
			t.Errorf("missing discovery, scan and snapshot regression for %s", agent)
		}
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

func TestArchivedGeminiSettingsWithComments(t *testing.T) {
	archive := portablePluginZIP(t, map[string]string{
		".gemini/settings.json": `{// comment retained in a captured archive
			"mcpServers":{"example":{"httpUrl":"https://example.invalid/mcp"}}
		}`,
	})
	_, raw := runCheckpoint(t, []string{"scan", "--profile", "custom", "--checks", "none", "--scope", "selected", "--format", "json", archive})
	var doc report.Document
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Validate() != nil || len(doc.Run.Targets) != 1 {
		t.Fatalf("invalid archive scan: %v: %s", err, raw)
	}
	graph := doc.Run.Targets[0].Analysis.Components
	if !slices.ContainsFunc(graph.Components, func(c report.Component) bool {
		return c.Host == report.HostGeminiCLI && c.Kind == "mcp_server" && c.Source != nil
	}) {
		t.Fatalf("missing Gemini MCP declaration: %+v", graph)
	}
}

func TestNativeSkillAssetsDoNotRegisterPlugins(t *testing.T) {
	for host, location := range map[string]string{
		report.HostQwenCode: ".qwen", report.HostKimiCode: ".kimi-code",
	} {
		t.Run(host, func(t *testing.T) {
			home := t.TempDir()
			root := location + "/skills/example/"
			writeNativeFixture(t, home, root+"SKILL.md", "# Example\nFormat text.\n")
			manifest := writeNativeFixture(t, home, root+"plugin.json", `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"example-data"}`)
			code, raw := runCheckpoint(t, []string{"discover", "--agent", host, "--home", home, "--system=false", "--no-project", "--format", "json"})
			var inventory discovery.Snapshot
			if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
				t.Fatalf("invalid inventory, exit %d: %s", code, raw)
			}
			if len(inventory.Components) != 1 || inventory.Components[0].Kind != "skill" || inventory.Components[0].Name != "example" ||
				slices.ContainsFunc(inventory.Sources, func(source discovery.Source) bool { return source.Path == manifest }) {
				t.Fatalf("a skill asset was treated as an installed plugin: %+v", inventory)
			}
		})
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
		"deepseek-harness/skill/shared":      "unknown",
		"zcode/skill/shared":                 "unknown",
		"qwen-code/skill/shared":             "unknown",
		"kimi-code/skill/shared":             "unknown",
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

func TestDiscoveryAllAgentsCapturesEveryRegisteredHost(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeNativeFixture(t, project, ".git/HEAD", "ref: refs/heads/main\n")

	want := make(map[string]string)
	for _, fixture := range nativeFixtures() {
		if _, written := want[fixture.host]; written {
			continue
		}

		root := project
		if fixture.userConfig {
			root = home
		}
		want[fixture.host] = writeNativeFixture(t, root, fixture.config, fixture.initial)
	}

	args := []string{"discover", "--home", home, "--project", project, "--agent", discovery.AllAgents, "--system=false"}
	code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
	var inventory discovery.Snapshot
	if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete {
		t.Fatalf("incomplete combined discovery, exit %d: %s", code, raw)
	}
	for _, agent := range discovery.AgentSelectors() {
		if agent != discovery.AllAgents && !slices.ContainsFunc(inventory.Components, func(c discovery.Component) bool {
			return c.Agent == agent && c.Source == want[agent]
		}) {
			t.Errorf("combined discovery omitted %s (%s)", agent, want[agent])
		}
	}

	scan := append(slices.Clone(args), "--scan", "--", "--profile", "custom", "--checks", "none", "--format", "json", "--scope", "selected")
	code, raw = runCheckpoint(t, scan)
	var doc report.Document
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Validate() != nil || code != 2 || len(doc.Run.Targets) != len(inventory.Targets) {
		t.Fatalf("invalid combined scan, exit %d, state %s, problems %+v", code, doc.Run.State, doc.Run.Problems)
	}
	for _, source := range want {
		if !slices.ContainsFunc(doc.Run.Targets, func(c report.TargetResult) bool {
			return c.Label == source && len(c.Analysis.Artifact.Files) != 0
		}) {
			t.Errorf("combined scan omitted captured source %s", source)
		}
	}
}

func TestArchivedCodexComparisonRecoversDiscoveryHost(t *testing.T) {
	home := t.TempDir()
	file := writeNativeFixture(t, home, ".codex/config.toml", "[mcp_servers.example]\nurl = 'https://example.invalid/old'\n")
	before, after := filepath.Join(t.TempDir(), "before.json"), filepath.Join(t.TempDir(), "after.json")
	args := []string{
		"discover", "--agent", report.HostCodex, "--home", home, "--no-project", "--system=false", "--kind", "mcp-server",
		"--snapshot", before, "--", "--harness", report.HostAuto, "--profile", "custom", "--checks", "none", "--scope", "selected",
	}
	// Simulate a checkpoint from before discovery selected the Codex parser.
	if code, raw := runCheckpoint(t, args); code != 2 {
		t.Fatalf("unexpected legacy snapshot exit %d: %s", code, raw)
	}

	writeNativeFixture(t, home, ".codex/config.toml", "[mcp_servers.example]\nurl = 'https://example.invalid/new'\n")
	code, raw := runCheckpoint(t, checkpointArgs("compare", before, "--scope", "selected", "--save-candidate", after))
	live := comparisonResult(t, raw)
	if code != 2 || len(live.Roots) != 1 || live.Roots[0].Change != "modified" {
		t.Fatalf("live comparison failed, exit %d: %+v", code, live.Roots)
	}
	assertNativeGraph(t, live.Previous, report.HostCodex, "mcp_server")
	assertNativeGraph(t, live.Current, report.HostCodex, "mcp_server")

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	code, raw = runCheckpoint(t, checkpointArgs("compare", before, "--scope", "selected", "--candidate", after))
	offline := comparisonResult(t, raw)
	if code != 2 || offline.Before != live.Before || offline.After != live.After ||
		len(offline.Roots) != 1 || offline.Roots[0].Change != "modified" {
		t.Fatalf("archived comparison omitted captured changes, exit %d: %+v", code, offline.Roots)
	}
	assertNativeGraph(t, offline.Previous, report.HostCodex, "mcp_server")
	assertNativeGraph(t, offline.Current, report.HostCodex, "mcp_server")
}
