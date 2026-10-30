package discovery_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/scout/internal/discovery"
)

func TestDiscoverScopesProvenanceAndPassiveMCP(t *testing.T) {
	home := canonicalTemp(t)
	project := filepath.Join(home, "work")
	write(t, project, ".git/HEAD", "fixture")
	const config = "[mcp_servers.local]\ncommand = 'sh'\nargs = ['-c', 'touch NEVER_EXECUTE']\nenabled = false\n[mcp_servers.remote]\nurl = 'https://example.invalid/mcp?secret=NEVER_OUTPUT'\n[plugins.'helper@market']\nenabled = false\n[[skills.config]]\npath = '/metadata/only'\nenabled = false\n"
	write(t, home, ".codex/config.toml", config)
	write(t, home, ".agents/skills/user/SKILL.md", "Instructions NEVER_OUTPUT")
	write(t, home, ".codex/skills/.system/builtin/SKILL.md", "Built in")
	write(t, home, ".codex/plugins/cache/market/helper/1/.codex-plugin/plugin.json", `{"name":"helper","skills":"./extra","mcpServers":"./config/mcp.json"}`)
	write(t, home, ".codex/plugins/cache/market/helper/1/extra/additional/SKILL.md", "Extra")
	write(t, home, ".codex/plugins/cache/market/helper/1/config/mcp.json", `{"mcpServers":{"bundled":{"command":"NEVER_EXECUTE"}}}`)
	write(t, home, ".claude.json", `{"mcpServers":{"user":{"command":"NEVER_EXECUTE"}},"projects":{`+quoted(project)+`:{"mcpServers":{"local":{"command":"NEVER_EXECUTE"}},"disabledMcpServers":["user"]},"/unselected":{"mcpServers":{"excluded":{}}}}}`)
	write(t, home, ".claude/settings.json", `{"enabledPlugins":{"helper@market":false}}`)
	write(t, home, ".claude/skills/personal/SKILL.md", "Personal")
	write(t, home, ".claude/commands/legacy.md", "Legacy command")
	write(t, project, ".agents/skills/project/SKILL.md", "Project")
	write(t, project, ".mcp.json", `{"mcpServers":{"project":{"url":"https://example.invalid"}}}`)

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	write(t, home, ".claude/plugins/cache/market/portable/1/.claude-plugin/plugin.json", `{"name":"claude-plugin","mcpServers":{"passive":{"url":`+quoted(server.URL)+`}}}`)

	o := options(home)
	o.Projects = []string{project}
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || !result.Complete || len(result.Issues) != 0 {
		t.Fatalf("unexpected discovery: err=%v issues=%+v", err, result.Issues)
	}

	for _, expected := range []struct{ agent, kind, name, scope, state string }{
		{"codex", "mcp-server", "local", "user", "disabled"},
		{"codex", "skill", "builtin", "user", "unknown"},
		{"codex", "skill", "project", "project", "unknown"},
		{"codex", "skill", "additional", "plugin", "unknown"},
		{"codex", "mcp-server", "bundled", "plugin", "unknown"},
		{"claude-code", "mcp-server", "local", "project", "unknown"},
		{"claude-code", "mcp-server", "project", "project", "unknown"},
		{"claude-code", "command", "legacy", "user", "unknown"},
		{"claude-code", "mcp-server", "passive", "plugin", "unknown"},
	} {
		if !slices.ContainsFunc(result.Components, func(c discovery.Component) bool {
			return c.Agent == expected.agent && c.Kind == expected.kind && c.Name == expected.name && c.Scope == expected.scope && c.State == expected.state
		}) {
			t.Errorf("missing declaration %+v", expected)
		}
	}

	if len(result.Enablement) != 4 || requests.Load() != 0 {
		t.Fatalf("enablement=%+v network requests=%d", result.Enablement, requests.Load())
	}

	wire, _ := json.Marshal(result)
	if strings.Contains(string(wire), "NEVER_OUTPUT") || strings.Contains(string(wire), "NEVER_EXECUTE") || strings.Contains(string(wire), "excluded") {
		t.Fatalf("inventory leaked content or unrelated project registration: %s", wire)
	}

	hash := sha256.Sum256([]byte(config))
	if !slices.Contains(result.Sources, discovery.Source{Path: filepath.Join(home, ".codex/config.toml"), SHA256: hex.EncodeToString(hash[:])}) {
		t.Fatal("configuration bytes have no source-bound hash")
	}

	if _, err := os.Stat(filepath.Join(home, "NEVER_EXECUTE")); !os.IsNotExist(err) {
		t.Fatal("MCP command was executed")
	}

	again, err := discovery.Discover(context.Background(), o)
	if err != nil || !reflect.DeepEqual(result, again) {
		t.Fatal("unchanged environment did not yield deterministic inventory")
	}
}

func TestPortablePluginAndAncestorBoundary(t *testing.T) {
	home := canonicalTemp(t)
	project := filepath.Join(home, "repo")
	write(t, project, ".git/HEAD", "fixture")
	write(t, project, "nested/.keep", "")
	write(t, project, ".agents/skills/inherited/SKILL.md", "Inherited")
	write(t, home, ".codex/plugins/cache/m/p/1/plugin.json", `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"portable","extensions":{"com.openai":{"skills":"./ignored"}}}`)
	write(t, home, ".codex/plugins/cache/m/p/1/skills/portable-skill/SKILL.md", "Portable")
	write(t, home, ".codex/plugins/cache/m/p/1/mcp.json", `{"mcpServers":{"portable-server":{"type":"streamable-http","url":"https://example.invalid"}}}`)
	write(t, home, ".codex/plugins/cache/m/p/1/ignored/should-not-load/SKILL.md", "Ignored overlay")
	write(t, home, ".codex/plugins/marketplaces/catalog/.codex-plugin/plugin.json", `{"name":"not-installed"}`)
	o := options(home)
	o.Agent, o.Projects = "codex", []string{filepath.Join(project, "nested"), project}
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || !result.Complete {
		t.Fatalf("discovery failed: %v %+v", err, result.Issues)
	}

	for _, name := range []string{"inherited", "portable", "portable-skill", "portable-server"} {
		if !slices.ContainsFunc(result.Components, func(c discovery.Component) bool { return c.Name == name }) {
			t.Errorf("missing %q", name)
		}
	}

	if slices.ContainsFunc(result.Components, func(c discovery.Component) bool { return c.Name == "should-not-load" || c.Name == "not-installed" }) {
		t.Fatal("portable overlay or marketplace catalog expanded the inventory")
	}

	if !slices.Contains(result.Targets, filepath.Join(project, ".agents/skills")) ||
		!slices.Contains(result.Targets, filepath.Join(home, ".codex/plugins/cache")) {
		t.Fatalf("missing grouped scan roots: %v", result.Targets)
	}

	for i, parent := range result.Targets {
		for j, child := range result.Targets {
			if i != j && strings.HasPrefix(child, parent+string(filepath.Separator)) {
				t.Fatalf("redundant scan target: %q inside %q", child, parent)
			}
		}
	}
}

func TestRefuseLinksAndEscapingPluginReferences(t *testing.T) {
	home, outside := canonicalTemp(t), canonicalTemp(t)
	write(t, outside, "payload/SKILL.md", "SECRET_OUTSIDE")
	write(t, home, ".codex/plugins/cache/m/p/1/.codex-plugin/plugin.json", `{"name":"escape","skills":"../../../../../../outside","mcpServers":"https://example.invalid/mcp"}`)
	write(t, home, ".agents/skills/.keep", "")
	if err := os.Symlink(filepath.Join(outside, "payload"), filepath.Join(home, ".agents/skills/link")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}

	o := options(home)
	o.Agent = "codex"
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || result.Complete || !hasIssue(result, "symlink_refused") || !hasIssue(result, "external_plugin_reference") {
		t.Fatalf("unsafe references were not reported: err=%v result=%+v", err, result)
	}

	for _, source := range result.Sources {
		if strings.HasPrefix(source.Path, outside+string(filepath.Separator)) {
			t.Fatal("discovery escaped the selected roots")
		}
	}
}

func TestPluginArrayEvidenceAndMissingDeclaredDirectory(t *testing.T) {
	home := canonicalTemp(t)
	write(t, home, ".codex/plugins/cache/m/p/1/.codex-plugin/plugin.json", `{"name":"mixed","skills":"./missing","mcpServers":[{"first":{}},{"second/name":{}}]}`)
	o := options(home)
	o.Agent = "codex"
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || result.Complete || !hasIssue(result, "referenced_directory_unavailable") {
		t.Fatalf("missing declared directory was hidden: %v %+v", err, result.Issues)
	}

	if !slices.ContainsFunc(result.Components, func(c discovery.Component) bool {
		return c.Name == "second/name" && c.Key == "/mcpServers/1/second~1name"
	}) {
		t.Fatalf("inline array evidence has the wrong source key: %+v", result.Components)
	}
}

func TestClaudePluginWithoutManifestKeepsDefaultComponentsAndScanRoot(t *testing.T) {
	home := canonicalTemp(t)
	const plugin = ".claude/plugins/cache/market/manifestless/1"
	write(t, home, plugin+"/skills/hidden/SKILL.md", "Untrusted instructions")
	write(t, home, plugin+"/.mcp.json", `{"mcpServers":{"bundled":{"command":"never-run"}}}`)
	o := options(home)
	o.Agent = "claude-code"
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || !result.Complete {
		t.Fatalf("default plugin layout failed: %v %+v", err, result.Issues)
	}

	for _, want := range []struct{ kind, name string }{{"plugin", "manifestless"}, {"skill", "hidden"}, {"mcp-server", "bundled"}} {
		if !slices.ContainsFunc(result.Components, func(c discovery.Component) bool {
			return c.Kind == want.kind && c.Name == want.name && c.Scope == "plugin" && c.Plugin == "manifestless"
		}) {
			t.Errorf("missing default component %+v: %+v", want, result.Components)
		}
	}

	if !slices.Contains(result.Targets, filepath.Join(home, ".claude/plugins/cache")) {
		t.Fatal("manifestless plugin was omitted from scan targets")
	}

	for _, c := range result.Components {
		if !slices.ContainsFunc(result.Sources, func(s discovery.Source) bool { return s.Path == c.Source && s.SHA256 != "" }) {
			t.Fatalf("invented component source: %+v", c)
		}
	}
}

func TestClaudePluginRootSkillFallback(t *testing.T) {
	for _, layout := range []string{"manifest", "manifestless", "skills-directory", "declared-skills"} {
		t.Run(layout, func(t *testing.T) {
			home := canonicalTemp(t)
			const plugin = ".claude/plugins/cache/market/single/1"
			manifest := `{"name":"single"}`
			if layout == "declared-skills" {
				manifest = `{"name":"single","skills":"./extra"}`
				write(t, home, plugin+"/extra/declared/SKILL.md", "Declared")
			}
			if layout != "manifestless" {
				write(t, home, plugin+"/.claude-plugin/plugin.json", manifest)
			}
			if layout == "skills-directory" {
				if err := os.MkdirAll(filepath.Join(home, plugin, "skills"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write(t, home, plugin+"/SKILL.md", "Root skill")
			o := options(home)
			o.Agent = "claude-code"
			result, err := discovery.Discover(context.Background(), o)
			if err != nil || !result.Complete {
				t.Fatalf("plugin discovery failed: %v %+v", err, result.Issues)
			}

			root := filepath.Join(home, plugin)
			found := slices.ContainsFunc(result.Components, func(c discovery.Component) bool {
				return c.Kind == "skill" && c.Path == root && c.Scope == "plugin" && c.Source == filepath.Join(root, "SKILL.md")
			})
			want := layout == "manifest" || layout == "manifestless"
			if found != want {
				t.Fatalf("root skill found=%t want=%t: %+v", found, want, result.Components)
			}
		})
	}
}

func TestPluginCacheScanCoverageDoesNotDependOnManifestMetadata(t *testing.T) {
	for _, hasFile := range []bool{false, true} {
		t.Run(strconv.FormatBool(hasFile), func(t *testing.T) {
			home := canonicalTemp(t)
			root := filepath.Join(home, ".claude/plugins/cache")
			if err := os.MkdirAll(filepath.Join(root, "market/opaque/1/hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if hasFile {
				write(t, root, "market/opaque/1/hooks/opaque.py", "# Unclassified supporting file")
			}
			o := options(home)
			o.Agent = "claude-code"
			result, err := discovery.Discover(context.Background(), o)
			if err != nil || !result.Complete || slices.Contains(result.Targets, root) != hasFile {
				t.Fatalf("cache file coverage lost: err=%v snapshot=%+v", err, result)
			}
		})
	}
}

func TestSelectedProjectAliasKeepsInlineMCPRegistrations(t *testing.T) {
	home := canonicalTemp(t)
	project := filepath.Join(home, "repo")
	write(t, project, ".git/HEAD", "Fixture")
	alias := filepath.Join(home, "repo-link")
	if err := os.Symlink(project, alias); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	write(t, home, ".claude.json", `{"projects":{`+quoted(project)+`:{"mcpServers":{"canonical":{"command":"never-run"}}},`+quoted(alias)+`:{"mcpServers":{"alias":{"command":"never-run"}}}}}`)
	o := options(home)
	o.Agent, o.Projects = "claude-code", []string{alias}
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || !result.Complete {
		t.Fatalf("alias discovery failed: %v %+v", err, result.Issues)
	}

	for _, name := range []string{"canonical", "alias"} {
		if !slices.ContainsFunc(result.Components, func(c discovery.Component) bool { return c.Kind == "mcp-server" && c.Name == name }) {
			t.Errorf("selected alias lost %q registration: %+v", name, result.Components)
		}
	}
}

func TestClaudeProjectMCPSwitchesRetainScopeAndEvidence(t *testing.T) {
	home := canonicalTemp(t)
	project := filepath.Join(home, "repo")
	write(t, project, ".git/HEAD", "Fixture")
	write(t, home, ".claude.json", `{"projects":{`+quoted(project)+`:{"mcpServers":{"private":{"command":"never-run"}},"disabledMcpServers":["private"],"enabledMcpServers":["computer-use"]},"/unselected":{"disabledMcpServers":["excluded"]}}}`)
	write(t, project, ".claude/settings.json", `{"disabledMcpServers":["not-a-setting"],"enabledMcpjsonServers":["approved"]}`)
	o := options(home)
	o.Agent, o.Projects = "claude-code", []string{project}
	result, err := discovery.Discover(context.Background(), o)
	if err != nil || !result.Complete {
		t.Fatalf("project switches failed: %v %+v", err, result.Issues)
	}
	for _, want := range []struct{ name, state, key string }{
		{"private", "disabled", "disabledMcpServers"}, {"computer-use", "enabled", "enabledMcpServers"},
	} {
		key := "/projects/" + strings.ReplaceAll(strings.ReplaceAll(project, "~", "~0"), "/", "~1") + "/" + want.key + "/0"
		if !slices.ContainsFunc(result.Enablement, func(e discovery.Enablement) bool {
			return e.Kind == "mcp-server" && e.Selector == want.name && e.State == want.state && e.Scope == "project" &&
				e.Project == project && e.Source == filepath.Join(home, ".claude.json") && e.Key == key
		}) {
			t.Errorf("missing project switch %+v: %+v", want, result.Enablement)
		}
	}
	if len(result.Enablement) != 3 || !slices.ContainsFunc(result.Enablement, func(e discovery.Enablement) bool { return e.Selector == "approved" }) {
		t.Fatalf("invented runtime settings or lost approvals: %+v", result.Enablement)
	}
}

func TestMalformedProjectMCPSwitchesRemainIncomplete(t *testing.T) {
	for _, bad := range []string{`"disabledMcpServers":"private"`, `"enabledMcpServers":[false]`} {
		t.Run(bad, func(t *testing.T) {
			home := canonicalTemp(t)
			project := filepath.Join(home, "repo")
			write(t, project, ".git/HEAD", "Fixture")
			write(t, home, ".claude.json", `{"projects":{`+quoted(project)+`:{"mcpServers":{"retained":{}},`+bad+`}}}`)
			o := options(home)
			o.Agent, o.Projects = "claude-code", []string{project}
			result, err := discovery.Discover(context.Background(), o)
			if err != nil || result.Complete || !hasIssue(result, "invalid_enablement") || len(result.Components) != 1 {
				t.Fatalf("invalid project switches were hidden: %v %+v", err, result)
			}
		})
	}
}

func TestMalformedAndBoundedDiscoveryRemainIncomplete(t *testing.T) {
	for _, kind := range []string{"duplicate-json", "duplicate-toml", "nonregular", "bytes", "entries", "depth"} {
		t.Run(kind, func(t *testing.T) {
			home := canonicalTemp(t)
			o := options(home)
			switch kind {
			case "duplicate-json":
				write(t, home, ".claude.json", `{"mcpServers":{"x":{},"x":{"command":"SECRET"}}}`)
			case "duplicate-toml":
				write(t, home, ".codex/config.toml", "[mcp_servers.x]\ncommand='one'\ncommand='SECRET'\n")
			case "nonregular":
				if err := os.MkdirAll(filepath.Join(home, ".codex/config.toml"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "bytes":
				write(t, home, ".codex/config.toml", strings.Repeat("# oversized\n", 100))
				o.MaxBytes = 16
			case "entries":
				o.MaxEntries = 2
			case "depth":
				write(t, home, ".agents/skills/group/too/deep/SKILL.md", "Deep")
				o.MaxDepth = 1
			}

			result, err := discovery.Discover(context.Background(), o)
			if err != nil || result.Complete || len(result.Issues) == 0 {
				t.Fatalf("failure became complete: err=%v result=%+v", err, result)
			}

			wire, _ := json.Marshal(result)
			if strings.Contains(string(wire), "SECRET") {
				t.Fatal("parser diagnostics copied configuration content")
			}
		})
	}
}

func TestCancellationAndInvalidOptions(t *testing.T) {
	o := options(canonicalTemp(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := discovery.Discover(ctx, o)
	if err == nil || result.Complete || !hasIssue(result, "cancelled") {
		t.Fatalf("cancellation lost: err=%v result=%+v", err, result)
	}

	if _, err := discovery.Discover(nil, o); err == nil {
		t.Fatal("nil context accepted")
	}

	o.MaxEntries = 0
	if _, err := discovery.Discover(context.Background(), o); err == nil {
		t.Fatal("unbounded discovery accepted")
	}
}

func options(home string) discovery.Options {
	o := discovery.DefaultOptions(home)
	o.System = false
	return o
}

func canonicalTemp(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return root
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func quoted(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func hasIssue(s discovery.Snapshot, code string) bool {
	return slices.ContainsFunc(s.Issues, func(i discovery.Issue) bool { return i.Code == code })
}
