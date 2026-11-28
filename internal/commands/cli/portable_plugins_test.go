package cli_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
