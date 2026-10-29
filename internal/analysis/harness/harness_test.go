package harness_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestPluginLayouts(t *testing.T) {
	for _, tc := range []struct{ name, host, manifest, manifestPath string }{
		{
			name:         "claude",
			host:         "claude-code",
			manifest:     `{"name":"sample-plugin"}`,
			manifestPath: ".claude-plugin/plugin.json",
		},
		{
			name:         "codex",
			host:         "codex",
			manifest:     `{"name":"sample-plugin","skills":"./skills/"}`,
			manifestPath: ".codex-plugin/plugin.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				tc.manifestPath:        tc.manifest,
				"skills/demo/SKILL.md": "Summarize the supplied text.",
				"hooks/hooks.json":     `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo ready"}]}]}}`,
			}
			g := inspect(t, files, tc.host)
			if len(g.Plugins) != 1 || g.Plugins[0].Host != tc.host || g.Plugins[0].FormatStatus != "partial" {
				t.Fatalf("%+v", g.Plugins)
			}
			if len(nodes(g, "hook")) != 1 || !hasNode(g, "skill", "skills/demo/SKILL.md", "conditional") {
				t.Fatalf("missing components: %+v", g.Components)
			}
			if !hasReference(g, "unresolved", "external_command_not_materialized") {
				t.Fatal("external command assumed known")
			}
		})
	}
}

func TestManifestlessAndNoSkill(t *testing.T) {
	files := map[string]string{"hooks/hooks.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo hello"}]}]}}`}
	g := inspect(t, files, "claude-code")
	if len(g.Plugins) != 1 || len(nodes(g, "hook")) != 1 || len(nodes(g, "skill")) != 0 {
		t.Fatal("manifestless plugin not interpreted")
	}
	g = inspect(t, files, "codex")
	if !hasIssue(g, "plugin_manifest_missing") || g.Plugins[0].FormatStatus != "invalid" {
		t.Fatal("missing required manifest hidden")
	}
	g = inspect(t, files, "auto")
	if len(g.Plugins) != 0 {
		t.Fatal("auto invented installed plugin")
	}
}

func TestReplacementAndAdditivePaths(t *testing.T) {
	g := inspect(t, map[string]string{
		".claude-plugin/plugin.json": `{"name":"p","commands":"./other/","agents":[],"skills":"./more/"}`,
		"commands/old.md":            "old",
		"other/new.md":               "new",
		"agents/old.md":              "old",
		"skills/a/SKILL.md":          "a",
		"more/b/SKILL.md":            "b",
	}, "claude-code")
	for _, tc := range []struct{ kind, path, activation string }{{
		kind:       "command",
		path:       "commands/old.md",
		activation: "inactive_for_profile",
	}, {
		kind:       "command",
		path:       "other/new.md",
		activation: "conditional",
	}, {
		kind:       "agent",
		path:       "agents/old.md",
		activation: "inactive_for_profile",
	}, {
		kind:       "skill",
		path:       "skills/a/SKILL.md",
		activation: "conditional",
	}, {
		kind:       "skill",
		path:       "more/b/SKILL.md",
		activation: "conditional",
	}} {
		if !hasNode(g, tc.kind, tc.path, tc.activation) {
			t.Errorf("missing %+v", tc)
		}
	}
}

func TestCodexHooksReplaceDefault(t *testing.T) {
	files := map[string]string{
		".codex-plugin/plugin.json": `{"name":"p","hooks":"./custom.json"}`,
		"hooks/hooks.json":          `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo old"}]}]}}`,
		"custom.json":               `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo new"}]}]}}`,
	}
	g := inspect(t, files, "codex")
	if !hasNode(g, "hook", "hooks/hooks.json", "inactive_for_profile") || !hasNode(g, "hook", "custom.json", "conditional") {
		t.Fatal("override semantics lost")
	}
	files[".codex-plugin/plugin.json"] = `{"name":"p","hooks":"./hooks/hooks.json"}`
	g = inspect(t, files, "codex")
	if !hasNode(g, "hook", "hooks/hooks.json", "conditional") {
		t.Fatal("explicit default path stayed inactive")
	}
}

func TestManifestFailuresAndUnknowns(t *testing.T) {
	for _, tc := range []struct{ name, text, code, status string }{
		{
			name:   "duplicate",
			text:   `{"name":"first","\u006eame":"second"}`,
			code:   "plugin_json_invalid",
			status: "invalid",
		},
		{name: "malformed", text: `{"name":`, code: "plugin_json_invalid", status: "invalid"},
		{name: "wrongroot", text: `[]`, code: "plugin_object_expected", status: "invalid"},
		{name: "name", text: `{"name":42}`, code: "plugin_name_invalid", status: "invalid"},
		{
			name:   "path-type",
			text:   `{"name":"p","skills":false}`,
			code:   "plugin_component_path_type_invalid",
			status: "invalid",
		},
		{name: "unknown", text: `{"name":"p","autoApprove":true}`, code: "plugin_unknown_field", status: "partial"},
		{
			name:   "extension",
			text:   `{"name":"p","experimental":{"monitors":"./monitor.json"}}`,
			code:   "plugin_extension_unverified",
			status: "partial",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := inspect(t, map[string]string{".claude-plugin/plugin.json": tc.text}, "claude-code")
			if !hasIssue(g, tc.code) || g.Plugins[0].FormatStatus != tc.status {
				t.Fatalf("plugins=%+v issues=%+v", g.Plugins, g.Issues)
			}
		})
	}
}

func TestSafeReferenceBoundaries(t *testing.T) {
	for _, tc := range []struct{ value, reason string }{
		{value: "./../host.json", reason: "outside_package"}, {value: "/etc/shadow", reason: "nonlocal_reference"}, {
			value:  "C:\\file",
			reason: "nonlocal_reference",
		}, {
			value:  "https://example.invalid/hooks.json",
			reason: "nonlocal_reference",
		}, {
			value:  "${HOME}/private.json",
			reason: "symbolic_reference",
		}, {
			value:  "./missing.json",
			reason: "missing_component",
		}, {
			value:  "config.json",
			reason: "relative_prefix_required",
		},
	} {
		t.Run(tc.reason+tc.value, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"name": "p", "hooks": tc.value})
			g := inspect(t, map[string]string{".claude-plugin/plugin.json": string(raw)}, "claude-code")
			if !hasReference(g, "unresolved", tc.reason) {
				t.Fatalf("%+v", g.References)
			}
		})
	}
}

func TestLiteralHandlerResolution(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		resolved      bool
		reason        string
	}{
		{name: "root-variable", command: `"${CLAUDE_PLUGIN_ROOT}/scripts/check.sh"`, resolved: true, reason: ""},
		{name: "interpreter", command: `bash "${CLAUDE_PLUGIN_ROOT}/scripts/check.sh"`, resolved: true, reason: ""},
		{name: "go", command: `go run "${CLAUDE_PLUGIN_ROOT}/scripts/check.sh"`, resolved: true, reason: ""},
		{
			name:     "single-quotes",
			command:  `'${CLAUDE_PLUGIN_ROOT}/scripts/check.sh'`,
			resolved: false,
			reason:   "external_command_not_materialized",
		},
		{
			name:     "echo",
			command:  `echo "${CLAUDE_PLUGIN_ROOT}/scripts/check.sh"`,
			resolved: false,
			reason:   "external_command_not_materialized",
		},
		{name: "relative", command: `./scripts/check.sh`, resolved: false, reason: "working_directory_unknown"},
		{name: "substitution", command: `bash "$(echo scripts/check.sh)"`, resolved: false, reason: "dynamic_command"},
		{name: "pipeline", command: `echo hello | bash`, resolved: false, reason: "complex_shell_command"},
		{
			name:     "traversal",
			command:  `"${CLAUDE_PLUGIN_ROOT}/../outside.sh"`,
			resolved: false,
			reason:   "outside_package",
		},
		{name: "flags", command: `bash -c "echo ready"`, resolved: false, reason: "interpreter_arguments_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook, _ := json.Marshal(map[string]any{"hooks": map[string]any{"SessionStart": []any{map[string]any{"hooks": []any{map[string]any{
				"type":    "command",
				"command": tc.command,
			}}}}}})
			g := inspect(t, map[string]string{
				".claude-plugin/plugin.json": `{"name":"p"}`,
				"hooks/hooks.json":           string(hook),
				"scripts/check.sh":           "echo safe",
			}, "claude-code")
			if hasReference(g, "resolved", "captured_handler_not_runtime_proof") != tc.resolved {
				t.Fatalf("unexpected resolution %+v", g.References)
			}
			if tc.reason != "" && !hasReference(g, "unresolved", tc.reason) {
				t.Fatalf("missing reason %+v", g.References)
			}
		})
	}
}

func TestMultipleHostsAndPortableNotMerged(t *testing.T) {
	files := map[string]string{
		"plugin.json":                `{"name":"portable","extensions":{"com.openai":{"hooks":"./unknown.json"}}}`,
		".codex-plugin/plugin.json":  `{"name":"codex-p"}`,
		".claude-plugin/plugin.json": `{"name":"claude-p"}`,
	}
	g := inspect(t, files, "codex")
	if len(g.Plugins) != 3 || !hasIssue(g, "plugin_layout_unverified") {
		t.Fatal("identities merged")
	}
	for _, p := range g.Plugins {
		if p.Host == "unknown" && p.Activation != "unknown" {
			t.Fatal("unknown loader treated as provably inactive")
		}
		if p.Host == "claude-code" && p.Activation != "inactive_for_profile" {
			t.Fatal("other host claimed active")
		}
	}
}

func TestDuplicatePluginNamesKeepOwnership(t *testing.T) {
	g := inspect(t, map[string]string{
		"a/.claude-plugin/plugin.json": `{"name":"same"}`,
		"a/skills/s/SKILL.md":          "same text",
		"b/.claude-plugin/plugin.json": `{"name":"same"}`,
		"b/skills/s/SKILL.md":          "same text",
	}, "auto")
	if len(g.Plugins) != 2 || g.Plugins[0].ID == g.Plugins[1].ID {
		t.Fatal("plugin identities collapsed")
	}
	owners := map[string]bool{}
	for _, n := range nodes(g, "skill") {
		if n.PluginID != "" {
			owners[n.PluginID] = true
		}
	}
	if len(owners) != 2 {
		t.Fatal("ownership lost")
	}
}

func TestSkippedManifestAndBounds(t *testing.T) {
	g := harness.Discover(context.Background(), []report.File{{
		Path:   ".claude-plugin/plugin.json",
		Status: "skipped",
		Reason: "oversize",
	}}, nil, report.ExtractionReport{}, report.HarnessOptions{})
	if len(g.Plugins) != 1 || !hasIssue(g, "plugin_input_unavailable") {
		t.Fatal("skipped manifest disappeared")
	}
	files := map[string]string{}
	for i := 0; i < harness.Limits().Plugins+1; i++ {
		files[fmt.Sprintf("p%d/.claude-plugin/plugin.json", i)] = `{"name":"p"}`
	}
	g = inspect(t, files, "auto")
	if len(g.Plugins) != harness.Limits().Plugins || !hasIssue(g, "plugin_limit") {
		t.Fatal("plugin budget not visible")
	}
}

func TestCancellationAndInvalidHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g := harness.Discover(ctx, nil, nil, report.ExtractionReport{}, report.HarnessOptions{})
	if len(g.Plugins) != 0 {
		t.Fatal("empty cancelled input produced plugins", g)
	}
	// Empty input has no operations. A known file must still account for cancellation.
	g = harness.Discover(ctx, []report.File{{Path: "plugin.json"}}, nil, report.ExtractionReport{}, report.HarnessOptions{})
	if !hasIssue(g, "harness_cancelled") {
		t.Fatal(g)
	}
	g = harness.Discover(context.Background(), nil, nil, report.ExtractionReport{}, report.HarnessOptions{Host: "untrusted-host"})
	if !hasIssue(g, "invalid_harness_request") {
		t.Fatal(g)
	}
}

func TestGraphDeterminismAndRedaction(t *testing.T) {
	files := map[string]string{".codex-plugin/plugin.json": `{"name":"p","mcpServers":{"mcp_servers":{"api":{"url":"https://SECRET_SENTINEL@example.invalid","headers":{"Authorization":"SECRET_SENTINEL"}}}}}`}
	a := inspect(t, files, "codex")
	b := inspect(t, files, "codex")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic graph")
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "SECRET_SENTINEL") {
		t.Fatal("graph leaked source value")
	}
	if !hasReference(a, "unresolved", "remote_implementation_not_scanned") {
		t.Fatal("remote implementation silently accepted")
	}
}

func FuzzPluginDiscovery(f *testing.F) {
	for _, seed := range []string{`{"name":"p"}`, `{"name":"p","hooks":"./../outside.json"}`, `{"name":"p","hooks":{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo hello"}]}]}}}`, `{"name":"p","name":"other"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 16384 {
			t.Skip()
		}
		g := inspect(t, map[string]string{".claude-plugin/plugin.json": text}, "claude-code")
		if len(g.Plugins) != 1 {
			t.Fatal("manifest inventory lost")
		}
	})
}

func BenchmarkPluginDiscovery(b *testing.B) {
	fs := []artifact.File{artifact.NewFile(".claude-plugin/plugin.json", []byte(`{"name":"p"}`), false), artifact.NewFile("hooks/hooks.json", []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo hello"}]}]}}`), false)}
	s := artifact.New("directory", fs, nil, nil, true)
	docs := document.PrepareAll(context.Background(), s.Files())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness.Discover(context.Background(), s.Metadata().Files, docs, report.ExtractionReport{}, report.HarnessOptions{Host: "claude-code"})
	}
}

func TestInactiveInterpretationEdgesAndRepeatedDeclarationEvidence(t *testing.T) {
	files := map[string]string{
		".codex-plugin/plugin.json": `{"name":"p","hooks":["./hooks/hooks.json","./hooks/hooks.json"]}`,
		"hooks/hooks.json":          `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo ready"}]}]}}`,
	}
	g := inspect(t, files, "claude-code")
	for _, n := range g.Components {
		if n.PluginID != "" && n.Activation != "inactive_for_profile" {
			t.Fatal("wrong-profile node activation", n)
		}
	}
	declarations := 0
	for _, e := range g.Edges {
		if e.Activation != "inactive_for_profile" {
			t.Fatal("wrong-profile edge activation", e)
		}
		if e.Relation == "declares" && e.Source != nil && e.Source.Path == ".codex-plugin/plugin.json" {
			declarations++
		}
	}
	if declarations != 2 {
		t.Fatalf("two declaration occurrences collapsed: %d", declarations)
	}
}

func TestArchiveMetadataCannotImpersonatePackageAndUnreadConfig(t *testing.T) {
	for _, role := range []string{"decoded", "metadata", "archive_member"} {
		t.Run(role, func(t *testing.T) {
			f := artifact.NewFile("scout://derived/fake", []byte(`{"name":"p"}`), false)
			s := artifact.New("directory", []artifact.File{f}, nil, nil, true)
			x := report.ExtractionReport{Objects: []report.DerivedObject{{
				File:        f.Metadata(),
				ParentPath:  "archive.zip",
				MemberName:  ".claude-plugin/plugin.json",
				ExtractorID: "zip32",
				Role:        role,
			}}}
			g := harness.Discover(context.Background(), nil, document.PrepareAll(context.Background(), s.Files()), x, report.HarnessOptions{})
			want := 0
			if role == "archive_member" {
				want = 1
			}
			if len(g.Plugins) != want {
				t.Fatalf("role %s: %d plugins", role, len(g.Plugins))
			}
			validate(t, g, map[string]string{f.Metadata().Path: f.Content()})
		})
	}
	f := artifact.NewFile(".claude-plugin/plugin.json", []byte(`{"name":"p","hooks":"./custom.json"}`), false)
	s := artifact.New("directory", []artifact.File{f}, nil, nil, true)
	inventory := append(append([]report.File(nil), s.Metadata().Files...), report.File{
		Path:   "custom.json",
		Status: "skipped",
		Reason: "size_limit",
	})
	g := harness.Discover(context.Background(), inventory, document.PrepareAll(context.Background(), s.Files()), report.ExtractionReport{}, report.HarnessOptions{Host: "claude-code"})
	if !hasReference(g, "unresolved", "component_not_captured") {
		t.Fatal("unread config resolved as captured", g.References)
	}
}

func TestComponentBudgetHasNoDanglingReferences(t *testing.T) {
	files := map[string]string{".claude-plugin/plugin.json": `{"name":"p"}`}
	for i := 0; i < harness.Limits().Components+10; i++ {
		files[fmt.Sprintf("commands/c%05d.md", i)] = "safe"
	}
	g := inspect(t, files, "claude-code")
	if len(g.Components) != harness.Limits().Components || !hasIssue(g, "component_limit") {
		t.Fatal("component budget hidden")
	}
}

func TestContextBudgetKeepsFindingEvidence(t *testing.T) {
	g := report.ComponentGraph{}
	for i := range 40 {
		g.Components = append(g.Components, report.Component{
			ID:   strconv.Itoa(i),
			Kind: "hook",
			Path: "same",
			Host: "claude-code",
		})
	}
	findings := []report.Finding{{
		ID:       "original",
		RuleID:   "R",
		Severity: report.High,
		Location: report.Location{
			Path:      "same",
			ByteStart: 0,
			ByteEnd:   1,
		},
	}}
	before := findings[0]
	if !harness.Enrich(findings, g) || len(findings[0].Contexts) != 32 {
		t.Fatal("context budget hidden")
	}
	got := findings[0]
	got.Contexts = nil
	if !reflect.DeepEqual(before, got) {
		t.Fatal("enrichment changed source evidence")
	}
}

func TestDirectorySelectionDoesNotExhaustBudgetOnSiblingPlugins(t *testing.T) {
	files := map[string]string{}
	for i := range harness.Limits().Plugins {
		prefix := fmt.Sprintf("p%03d/", i)
		files[prefix+".claude-plugin/plugin.json"] = `{"name":"p"}`
		files[prefix+"skills/s/SKILL.md"] = "instructions"
		for j := range 30 {
			files[fmt.Sprintf("%sdata/%02d.txt", prefix, j)] = "data"
		}
	}
	g := inspect(t, files, "auto")
	if len(g.Plugins) != harness.Limits().Plugins || hasIssue(g, "harness_operation_limit") {
		t.Fatalf("plugins=%d issues=%+v", len(g.Plugins), g.Issues)
	}
	owned := 0
	for _, n := range g.Components {
		if n.Kind == "skill" && n.PluginID != "" {
			owned++
		}
	}
	if owned != harness.Limits().Plugins {
		t.Fatalf("discovered %d owned skills", owned)
	}
}

func TestSettingsCommandForms(t *testing.T) {
	for _, tc := range []struct {
		settings string
		commands int
		invalid  bool
	}{
		{settings: `{"apiKeyHelper":"echo ready"}`, commands: 1, invalid: false},
		{settings: `{"awsAuthRefresh":["echo","ready"]}`, commands: 1, invalid: false},
		{settings: `{"gcpAuthRefresh":["echo",1]}`, commands: 1, invalid: true},
		{settings: `{"otelHeadersHelper":[]}`, commands: 1, invalid: true},
		{settings: `{"statusLine":{"type":"command","command":"echo status"}}`, commands: 1, invalid: false},
		{settings: `{"fileSuggestion":{"type":"command","command":["echo","file"]}}`, commands: 1, invalid: false},
		{settings: `{"statusLine":{"type":"command"}}`, commands: 0, invalid: true},
		{settings: `{"statusLine":{"type":"text","command":"ignore"}}`, commands: 0, invalid: false},
		{
			settings: `{"disableAllHooks":true,"statusLine":{"type":"command","command":"echo status"}}`,
			commands: 0,
			invalid:  false,
		},
	} {
		t.Run(tc.settings, func(t *testing.T) {
			g := inspect(t, map[string]string{
				".claude-plugin/plugin.json": `{"name":"p"}`,
				"settings.json":              tc.settings,
			}, "claude-code")
			if len(nodes(g, "settings_command")) != tc.commands || hasIssue(g, "plugin_settings_command_invalid") != tc.invalid {
				t.Fatal(g)
			}
		})
	}
}

func TestHookAndServerDeclarationGrammar(t *testing.T) {
	for _, tc := range []struct{ file, text, issue string }{
		{file: "hooks/hooks.json", text: `{"hooks":{"SessionStart":{}}}`, issue: "plugin_hooks_invalid"},
		{file: "hooks/hooks.json", text: `{"hooks":{"SessionStart":[{}]}}`, issue: "plugin_hooks_invalid"},
		{
			file:  "hooks/hooks.json",
			text:  `{"hooks":{"SessionStart":[{"hooks":[{"type":"prompt","prompt":"Review"},{"type":"agent","prompt":""},{"type":"mcp_tool"},{"type":"http","url":"https://example.invalid"}]}]}}`,
			issue: "plugin_hook_prompt_invalid",
		},
		{
			file:  "hooks/hooks.json",
			text:  `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo","args":[1]}]}]}}`,
			issue: "plugin_hook_args_invalid",
		},
		{file: ".mcp.json", text: `{"mcpServers":{"api":{"command":"echo","args":["ready"]}}}`, issue: ""},
		{
			file:  ".mcp.json",
			text:  `{"mcpServers":{"api":{"command":"echo","args":[1]}}}`,
			issue: "plugin_server_command_invalid",
		},
		{
			file:  ".mcp.json",
			text:  `{"mcpServers":{"api":{"command":"echo","args":{}}}}`,
			issue: "plugin_server_command_invalid",
		},
		{file: ".mcp.json", text: `{"mcpServers":{"api":{"url":1}}}`, issue: "plugin_server_url_invalid"},
		{file: ".mcp.json", text: `{"mcpServers":{"api":{}}}`, issue: "plugin_server_transport_unverified"},
		{
			file:  ".mcp.json",
			text:  `{"mcpServers":{"api":{"command":"echo","url":"https://example.invalid"}}}`,
			issue: "plugin_server_transport_ambiguous",
		},
	} {
		t.Run(tc.text, func(t *testing.T) {
			g := inspect(t, map[string]string{
				".claude-plugin/plugin.json": `{"name":"p","dependencies":[{}],"experimental":{}}`,
				tc.file:                      tc.text,
			}, "claude-code")
			if tc.issue != "" && !hasIssue(g, tc.issue) {
				t.Fatal(g)
			}
			if tc.issue == "" && len(nodes(g, "mcp_server")) != 1 {
				t.Fatal(g)
			}
		})
	}
	for _, manifest := range []string{`{"name":"p","version":1,"keywords":[1],"dependencies":{}}`, `{"name":"p","skills":false}`} {
		g := inspect(t, map[string]string{".claude-plugin/plugin.json": manifest, "SKILL.md": "root instructions"}, "claude-code")
		if len(g.Plugins) != 1 || g.Plugins[0].FormatStatus != "invalid" {
			t.Fatal(g)
		}
	}
	g := inspect(t, map[string]string{".claude-plugin/plugin.json": `{"name":"p"}`, "SKILL.md": "root instructions"}, "claude-code")
	if !hasNode(g, "skill", "SKILL.md", "conditional") {
		t.Fatal(g)
	}
}

func TestHookWrapperFallbackAndUncertainSettingsRemainVisible(t *testing.T) {
	for _, text := range []string{`{"hooks":[]}`, `{"SessionStart":[]}`, `{"hooks":{"SessionStart":[{"hooks":[]}]}}`} {
		g := inspect(t, map[string]string{
			".claude-plugin/plugin.json": `{"name":"p"}`,
			"hooks/hooks.json":           text,
			"AGENTS.md":                  "instructions",
		}, "claude-code")
		if len(nodes(g, "host_config")) != 1 {
			t.Fatal(g)
		}
	}
	g := inspect(t, map[string]string{
		".claude-plugin/plugin.json": `{"name":"p"}`,
		"settings.json":              `{"disableAllHooks":"true","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo ready"}]}]}}`,
	}, "claude-code")
	if !hasIssue(g, "plugin_hook_disable_unverified") || len(nodes(g, "hook")) != 1 {
		t.Fatal(g)
	}
}

func TestContextOverlapAndConfigScopeBinding(t *testing.T) {
	source := &report.SourceRef{Path: "x", ByteStart: 3, ByteEnd: 8}
	graph := report.ComponentGraph{
		Components: []report.Component{{
			ID:     "handler",
			Kind:   "handler",
			Path:   "x",
			Source: source,
		}, {
			ID:   "hook",
			Kind: "hook",
			Path: "config",
		}},
		Edges: []report.ComponentEdge{{
			From:     "hook",
			To:       "handler",
			Relation: "invokes",
		}, {
			From:     "missing",
			To:       "handler",
			Relation: "invokes",
		}},
	}
	findings := []report.Finding{{Location: report.Location{Path: "x", ByteStart: 0, ByteEnd: 3}}, {Location: report.Location{
		Path:      "x",
		ByteStart: 4,
		ByteEnd:   7,
	}}}
	if harness.Enrich(findings, graph) || len(findings[0].Contexts) != 0 || len(findings[1].Contexts) != 2 {
		t.Fatal(findings)
	}
	files := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("x", []byte(`{"mcpServers":{}}`), false)})
	graph.Components = []report.Component{{Kind: "mcp_config", Host: "codex", Source: source}, {
		Kind:   "mcp_config",
		Host:   "codex",
		Source: source,
	}, {
		Kind:   "hook_config",
		Host:   "claude-code",
		Source: source,
	}, {
		Kind:   "skill",
		Source: source,
	}, {Kind: "hook_config"}}
	scoped := harness.ApplyConfigScopes(files, graph)
	if len(files[0].ConfigScopes()) != 0 || len(scoped[0].ConfigScopes()) != 2 {
		t.Fatal(scoped)
	}
}

func inspect(t testing.TB, contents map[string]string, host string) report.ComponentGraph {
	t.Helper()
	files := make([]artifact.File, 0, len(contents))
	for name, text := range contents {
		files = append(files, artifact.NewFile(name, []byte(text), false))
	}
	snapshot := artifact.New("directory", files, nil, nil, true)
	g := harness.Discover(context.Background(), snapshot.Metadata().Files, document.PrepareAll(context.Background(), snapshot.Files()), report.ExtractionReport{}, report.HarnessOptions{Host: host})
	validate(t, g, contents)
	return g
}

func validate(t testing.TB, g report.ComponentGraph, contents map[string]string) {
	t.Helper()
	ids := map[string]bool{}
	for _, n := range g.Components {
		if ids[n.ID] {
			t.Fatal("duplicate component")
		}
		ids[n.ID] = true
		checkSource(t, n.Source, contents)
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		if !ids[e.From] || !ids[e.To] || edges[e.ID] {
			t.Fatal("dangling or duplicate edge")
		}
		edges[e.ID] = true
		checkSource(t, e.Source, contents)
	}
	refs := map[string]bool{}
	for _, r := range g.References {
		if refs[r.ID] || !ids[r.ComponentID] {
			t.Fatal("bad reference identity")
		}
		refs[r.ID] = true
		if r.Status == "resolved" && !ids[r.TargetID] {
			t.Fatal("resolved without target")
		}
		checkSource(t, r.Source, contents)
	}
}

func checkSource(t testing.TB, s *report.SourceRef, contents map[string]string) {
	t.Helper()
	if s == nil {
		return
	}
	text, ok := contents[s.Path]
	if !ok || s.ByteStart < 0 || s.ByteEnd < s.ByteStart || s.ByteEnd > len(text) {
		t.Fatalf("invalid source %+v", s)
	}
	if s.SHA256 != artifact.Hash([]byte(text)) || s.SpanSHA256 != artifact.Hash([]byte(text[s.ByteStart:s.ByteEnd])) {
		t.Fatal("evidence hash mismatch")
	}
}

func hasIssue(g report.ComponentGraph, code string) bool {
	for _, i := range g.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func nodes(g report.ComponentGraph, kind string) []report.Component {
	var out []report.Component
	for _, n := range g.Components {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func hasNode(g report.ComponentGraph, kind, path, activation string) bool {
	for _, n := range g.Components {
		if n.Kind == kind && n.Path == path && (activation == "" || n.Activation == activation) {
			return true
		}
	}
	return false
}

func hasReference(g report.ComponentGraph, status, reason string) bool {
	for _, r := range g.References {
		if r.Status == status && r.Reason == reason {
			return true
		}
	}
	return false
}
