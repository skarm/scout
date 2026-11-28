package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestGeminiExtensionNativeComponents(t *testing.T) {
	const manifest = "gemini-extension.json"
	g := inspect(t, map[string]string{
		manifest:                    `{"name":"demo","version":"1.0.0","contextFileName":["docs/CONTEXT.md","../outside.md"],"mcpServers":{"local":{"command":"${extensionPath}/bin/server.sh"},"remote":{"httpUrl":"https://example.invalid/mcp"}}}`,
		"docs/CONTEXT.md":           "Format the supplied text.",
		"GEMINI.md":                 "Default context.",
		"commands/team/format.toml": "prompt = 'Format text.'",
		"policies/example.toml":     "[[rule]]\ndecision = 'ask_user'\n",
		"agents/formatter.md":       "Format text.",
		"skills/format/SKILL.md":    "Format text.",
		"skills/deep/path/SKILL.md": "Outside the skill layout.",
		"bin/server.sh":             "printf 'server\\n'\n",
		"hooks/hooks.json":          `{"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"printf hello"}]}]}}`,
	}, report.HostAuto)

	if len(g.Plugins) != 1 || g.Plugins[0].Host != report.HostGeminiCLI {
		t.Fatalf("wrong extension interpretation: %+v", g.Plugins)
	}

	for _, want := range []struct{ kind, file string }{
		{"rule", "docs/CONTEXT.md"},
		{"rule", "policies/example.toml"},
		{"command", "commands/team/format.toml"},
		{"agent", "agents/formatter.md"},
		{report.ComponentHook, "hooks/hooks.json"},
		{"handler", "bin/server.sh"},
	} {
		if !hasNode(g, want.kind, want.file, "") {
			t.Errorf("missing %s in %s", want.kind, want.file)
		}
	}

	if hasNode(g, "rule", "GEMINI.md", "") {
		t.Fatal("extension interpreted the overridden context")
	}

	if !slices.ContainsFunc(g.Components, func(c report.Component) bool {
		return c.Host == report.HostGeminiCLI && c.Kind == report.ComponentSkill && c.Path == "skills/format/SKILL.md"
	}) || slices.ContainsFunc(g.Components, func(c report.Component) bool {
		return c.Host == report.HostGeminiCLI && c.Kind == report.ComponentSkill && c.Path == "skills/deep/path/SKILL.md"
	}) {
		t.Fatal("unexpected Gemini extension skill layout")
	}

	if len(nodes(g, "mcp_server")) != 2 || !hasReference(g, report.ReferenceUnresolved, "remote_implementation_not_scanned") ||
		!hasReference(g, report.ReferenceUnresolved, "missing_or_unsupported_component") {
		t.Fatalf("missing MCP declaration or out-of-package diagnostics: %+v", g.References)
	}
}

func TestGeminiWorkspaceDoesNotTreatExtensionPathAsLocal(t *testing.T) {
	g := inspect(t, map[string]string{
		".gemini/settings.json": `{"mcpServers":{"local":{"command":"${extensionPath}/bin/server.sh"}}}`,
		"bin/server.sh":         "printf 'server\\n'\n",
	}, report.HostAuto)

	if !hasNode(g, "mcp_server", ".gemini/settings.json", "") || hasNode(g, "handler", "bin/server.sh", "") {
		t.Fatalf("unexpected Gemini workspace references: %+v", g.Components)
	}
}
