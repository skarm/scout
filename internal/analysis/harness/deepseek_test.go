package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestDeepSeekBundleSelectsOnlyContainedCapturedPatches(t *testing.T) {
	g := inspect(t, map[string]string{
		"package.json": `{"name":"test-bundle","dsh":{"bundle":{"patch":["config/custom.yml","../outside.yml","missing.yml"]}}}`,
		"config/custom.yml": `- insert:
    - name: cordis:group
      disabled: true
      config:
        - name: '@deepseek-ai/dsh-mcp-manager'
          config:
            servers:
              local:
                enabled: true
                command: printf
                transport: stdio
    - name: cordis:include
      config: { path: ../unrelated.yml }
`,
		"unrelated.yml": `- name: '@deepseek-ai/dsh-mcp-client'
  config: {serverName: unrelated, command: printf, transport: stdio}
`,
	}, report.HostAuto)
	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostDeepSeekHarness ||
		len(nodes(g, "mcp_server")) != 1 || !hasNode(g, "mcp_server", "config/custom.yml", "inactive_for_profile") ||
		!hasReference(g, report.ReferenceResolved, "captured_file") ||
		!hasReference(g, report.ReferenceUnresolved, "cordis_include_unverified") ||
		!hasReference(g, report.ReferenceUnresolved, report.ReferenceReasonComponentNotCaptured) {
		t.Fatalf("wrong DeepSeek bundle graph: %+v", g)
	}
}

func TestDeepSeekBundlePreparationLeavesCallerDocumentsUnchanged(t *testing.T) {
	t.Parallel()

	files := []artifact.File{
		artifact.NewFile("layer.yml", []byte("- name: '@deepseek-ai/dsh-mcp-client'\n  config: {serverName: demo, command: printf, transport: stdio}\n"), false),
		artifact.NewFile("package.json", []byte(`{"name":"sample","dsh":{"bundle":{"patch":"layer.yml"}}}`), false),
	}
	docs := document.PrepareAll(t.Context(), files)
	inventory := []report.File{files[0].Metadata(), files[1].Metadata()}

	for _, host := range []string{report.HostAuto, report.HostDeepSeekHarness} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()

			g := harness.Discover(t.Context(), inventory, docs, report.ExtractionReport{}, report.HarnessOptions{Host: host})
			if !hasNode(g, "mcp_server", "layer.yml", "") {
				t.Fatalf("missing bundle patch server: %+v", g)
			}

			if slices.ContainsFunc(docs[0].Units(), func(unit document.Unit) bool { return unit.ParserID == "cordis-yaml" }) {
				t.Fatal("a scan replaced the caller's original analysis units")
			}
		})
	}
}

func TestDeepSeekMalformedCordisRetainsNoPartialEntries(t *testing.T) {
	const file = "cordis.yml"
	g := inspect(t, map[string]string{
		file: `- name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: safe
    transport: streamable-http
    url: https://example.invalid/one
    url: https://example.invalid/two
`,
	}, report.HostAuto)
	if len(g.Plugins) != 1 || g.Plugins[0].FormatStatus != "invalid" || len(nodes(g, "mcp_server")) != 0 ||
		!slices.ContainsFunc(g.Issues, func(issue report.HarnessIssue) bool { return issue.Code == "plugin_yaml_invalid" && issue.Path == file }) {
		t.Fatalf("malformed Cordis YAML reached the graph: %+v", g)
	}
}
