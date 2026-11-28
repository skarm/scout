package cli_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/discovery"
	"github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestPortablePluginsDiscoverAndScan(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.1.0"} {
		t.Run(version, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".codex", "plugins", "cache", "market", "demo", version)
			files := map[string]string{
				"plugin.json":                `{"$schema":"https://agent-plugins.org/schemas/` + version + `/plugin.schema.json","name":"portable-demo"}`,
				"mcp.json":                   `{"$schema":"https://agent-plugins.org/schemas/` + version + `/mcp.schema.json","mcpServers":{"example":{"type":"stdio","command":"./scripts/run.sh","args":["one arg"]}}}`,
				"skills/demo/SKILL.md":       "---\nname: demo\ndescription: Format plain text.\n---\nFormat the provided text.\n",
				"skills/extra/deep/SKILL.md": "Other instructions.",
				"scripts/run.sh":             "#!/bin/sh\nprintf '%s\\n' ready\n",
				"hooks.json":                 `{"$schema":"https://agent-plugins.org/schemas/1.1.0/hooks.schema.json","hooks":{"SessionStart":[{"command":"./scripts/run.sh"}]}}`,
			}
			for name, content := range files {
				scenarios.WriteFile(t, root, name, content)
			}

			var out, diagnostics bytes.Buffer
			args := []string{"discover", "--agent", "codex", "--home", home, "--system=false", "--no-project", "--format", "json"}
			if code := cli.Run(context.Background(), args, &out, &diagnostics); code != 0 {
				t.Fatalf("discover exit %d: %s, %s", code, &diagnostics, &out)
			}
			var inventory discovery.Snapshot
			if err := json.Unmarshal(out.Bytes(), &inventory); err != nil || !inventory.Complete {
				t.Fatalf("discover: %v, %+v", err, inventory.Issues)
			}
			wantInventory := []string{"mcp-server:example", "plugin:portable-demo", "skill:demo"}
			wantLinks := 1
			if version == "1.1.0" {
				wantInventory = append([]string{"hook:SessionStart"}, wantInventory...)
				wantLinks++
			}
			gotInventory := make([]string, 0, len(inventory.Components))
			for _, component := range inventory.Components {
				gotInventory = append(gotInventory, component.Kind+":"+component.Name)
			}
			slices.Sort(gotInventory)
			if !slices.Equal(gotInventory, wantInventory) {
				t.Fatalf("inventory = %v, want %v", gotInventory, wantInventory)
			}
			archive := portablePluginZIP(t, files)
			for _, target := range []string{root, archive} {
				out.Reset()
				diagnostics.Reset()
				args := []string{"scan", "--profile", "custom", "--checks", "patterns", "--format", "json", "--scope", "selected", target}
				code := cli.Run(context.Background(), args, &out, &diagnostics)
				var document report.Document
				if json.Unmarshal(out.Bytes(), &document) != nil || document.Validate() != nil || len(document.Run.Targets) != 1 || code != policy.Code(document) {
					t.Fatalf("scan exit %d: %s, %s", code, &diagnostics, &out)
				}
				graph := document.Run.Targets[0].Analysis.Components
				if len(graph.Plugins) != 1 || graph.Plugins[0].Contract != "agent-plugins-"+version || graph.Plugins[0].Host != report.HostAgentPlugins {
					t.Fatalf("%s plugin interpretations: %+v", target, graph.Plugins)
				}
				id := graph.Plugins[0].ID
				var kinds []string
				for _, c := range graph.Components {
					if c.PluginID == id {
						kinds = append(kinds, c.Kind)
					}
				}
				slices.Sort(kinds)
				want := []string{"handler", "mcp_config", "mcp_server", "plugin", "skill"}
				if version == "1.1.0" {
					want = []string{"handler", "hook", "hook_config", "mcp_config", "mcp_server", "plugin", "skill"}
				}
				if !slices.Equal(kinds, want) {
					t.Fatalf("%s plugin components = %v, want %v", target, kinds, want)
				}
				links := 0
				for _, ref := range graph.References {
					if ref.Kind == "handler" && ref.Status == report.ReferenceResolved {
						links++
					}
				}
				if links != wantLinks {
					t.Fatalf("%s lost a handler reference: %+v", target, graph.References)
				}
			}
		})
	}
}

func TestPortableCodexNativeHookSelection(t *testing.T) {
	const hooks = `{"SessionStart":[{"hooks":[{"type":"command","command":"printf ready"}]}]}`
	for _, tt := range []struct {
		name, extension, fallback, source, key string
	}{
		{name: "default", source: "hooks/hooks.json", key: "/hooks/SessionStart/0/hooks/0"},
		{name: "fallback", fallback: `{"name":"portable-demo","hooks":"./settings/native.json"}`, source: "settings/native.json", key: "/SessionStart/0/hooks/0"},
		{
			name: "inline", extension: `,"extensions":{"com.openai":{"hooks":` + hooks + `}}`, fallback: `{"name":"portable-demo","hooks":"./settings/native.json"}`,
			source: "plugin.json", key: "/extensions/com.openai/hooks/SessionStart/0/hooks/0",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".codex", "plugins", "cache", "market", "demo", "1.1.0")
			writeNativeFixture(t, root, "plugin.json", `{"$schema":"https://agent-plugins.org/schemas/1.1.0/plugin.schema.json","name":"portable-demo"`+tt.extension+`}`)
			writeNativeFixture(t, root, "hooks/hooks.json", `{"hooks":`+hooks+`}`)
			if tt.fallback != "" {
				writeNativeFixture(t, root, ".codex-plugin/plugin.json", tt.fallback)
				writeNativeFixture(t, root, "settings/native.json", hooks)
			}
			root, err := filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"discover", "--agent", "codex", "--home", home, "--system=false", "--no-project", "--kind", "hook"}
			code, raw := runCheckpoint(t, append(slices.Clone(args), "--format", "json"))
			var inventory discovery.Snapshot
			if err := json.Unmarshal(raw, &inventory); err != nil || code != 0 || !inventory.Complete || !slices.Equal(inventory.Targets, []string{root}) {
				t.Fatalf("native hook selection, exit %d: %s", code, raw)
			}
			var discovered []discovery.Component
			for _, c := range inventory.Components {
				if c.Kind == "hook" {
					discovered = append(discovered, c)
				}
			}
			if len(discovered) != 1 || discovered[0].Source != filepath.Join(root, tt.source) || discovered[0].Key != tt.key {
				t.Fatalf("wrong native hook provenance: %+v", discovered)
			}
			scanFlags := []string{"--", "--profile", "custom", "--checks", "none", "--scope", "selected", "--format", "json"}
			_, raw = runCheckpoint(t, append(append(slices.Clone(args), "--scan"), scanFlags...))
			var doc report.Document
			if err := json.Unmarshal(raw, &doc); err != nil || doc.Validate() != nil {
				t.Fatalf("invalid selected scan: %v: %s", err, raw)
			}
			assertNativeGraph(t, &doc, report.HostCodex, report.ComponentHook)
			if tt.name == "default" {
				// Explicit auto reproduces the context captured before discovery carried
				// the Codex profile for packages with only default native hooks.
				checkpoint, candidate := filepath.Join(t.TempDir(), "before.json"), filepath.Join(t.TempDir(), "after.json")
				beforeArgs := append(append(slices.Clone(args), "--snapshot", checkpoint), scanFlags...)
				runCheckpoint(t, append(beforeArgs, "--harness", report.HostAuto))
				writeNativeFixture(t, root, tt.source, `{"hooks":`+strings.ReplaceAll(hooks, "printf ready", "printf updated")+`}`)
				code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--save-candidate", candidate))
				comparison := comparisonResult(t, raw)
				if code != 2 || len(comparison.Roots) != 1 || comparison.Roots[0].Change != "modified" {
					t.Fatalf("native hook edit missing from snapshot comparison: exit %d, %+v", code, comparison.Roots)
				}
				assertNativeGraph(t, comparison.Previous, report.HostCodex, report.ComponentHook)
				assertNativeGraph(t, comparison.Current, report.HostCodex, report.ComponentHook)

				code, raw = runCheckpoint(t, checkpointArgs("compare", checkpoint, "--scope", "selected", "--candidate", candidate))
				archived := comparisonResult(t, raw)
				if code != 2 || archived.Before != comparison.Before || archived.After != comparison.After {
					t.Fatalf("archived comparison lost the Codex context: exit %d, %+v", code, archived.Roots)
				}
				assertNativeGraph(t, archived.Previous, report.HostCodex, report.ComponentHook)
				assertNativeGraph(t, archived.Current, report.HostCodex, report.ComponentHook)
			}
		})
	}
}

func portablePluginZIP(t *testing.T, files map[string]string) string {
	t.Helper()
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	for name, content := range files {
		e, err := z.Create("portable/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "portable.zip")
	if err := os.WriteFile(file, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}
