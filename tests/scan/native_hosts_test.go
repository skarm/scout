package scout_test

import (
	"errors"
	"path"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/report"
)

func TestNativeConfigurationFindings(t *testing.T) {
	for _, tc := range []struct {
		host, file, config string
		rules              []string
	}{
		{
			host: report.HostCursor, file: ".cursor/hooks.json",
			config: `{"version":1,"hooks":{"beforeShellExecution":[{"command":"printf hello"}]}}`,
			rules:  []string{"AC003"},
		},
		{
			host: report.HostCopilotCLI, file: ".github/hooks/checks.json",
			config: `{"version":1,"hooks":{"preToolUse":[{"bash":"printf hello","powershell":"Write-Output hello"},{"type":"command","exec":"printf","args":["world"]}]}}`,
			rules:  []string{"AC003", "AC003", "AC003"},
		},
		{
			host: report.HostAuto, file: ".github/copilot/settings.local.json",
			config: `{"hooks":{"sessionStart":[{"command":"printf hello"}]}}`,
			rules:  []string{"AC003"},
		},
		{
			host: report.HostCopilotCLI, file: ".github/mcp.json",
			config: `{"api":{"type":"http","url":"http://example.invalid/mcp"}}`,
			rules:  []string{"MC001"},
		},
		{
			host: report.HostAuto, file: ".gemini/settings.json",
			config: `{// Source positions refer to the original settings file.
				"mcpServers":{"remote":{"httpUrl":"http://example.invalid/mcp"}},
				"disableAllHooks":true,
				"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"printf hello"}]}]}
			}`,
			rules: []string{"AC003", "MC001"},
		},
		{
			host: report.HostAuto, file: "gemini-extension.json",
			config: `{"name":"demo","version":"1.0.0","mcpServers":{"remote":{"httpUrl":"http://example.invalid/api"}}}`,
			rules:  []string{"MC001"},
		},
		{
			host: report.HostGeminiCLI, file: "settings.json",
			config: `{"disableAllHooks":true,"hooks":{"enabled":true,"BeforeTool":[{"hooks":[{"type":"command","command":"printf hello"}]}]}}`,
			rules:  []string{"AC003"},
		},
		{
			host: report.HostAuto, file: "openclaw.json",
			config: `{
				// Unquoted native keys and single-quoted values.
				mcp: { servers: {
					local: { command: 'npx', args: ['sample-mcp@latest'], },
					mcpServers: { url: 'http://example.invalid/mcp', enabled: false, },
				}, },
			}`,
			rules: []string{"MC001", "SC001"},
		},
		{
			host: report.HostOpenCode, file: "opencode.jsonc",
			config: `{// retain byte evidence
				"mcp": {"servers": {
					"example":{"type":"local","command":["npx","example-mcp@latest"],"environment":{"API_TOKEN":"{env:SCOUT_TEST_TOKEN}"},},
					"remote":{"type":"remote","url":"http://example.invalid/mcp","disabled":true},
				},},
			}`,
			rules: []string{"MC001", "SC001"},
		},
		{
			host: report.HostAuto, file: ".grok/config.toml",
			config: "[mcp_servers.remote]\nurl = 'http://example.invalid/mcp'\n" +
				"[mcp_servers.local]\ncommand = 'npx'\nargs = ['example-mcp@latest']\n",
			rules: []string{"MC001", "SC001"},
		},
		{
			host: report.HostGrokCLI, file: "managed_config.toml",
			config: "[[hooks.SessionStart]]\nhooks = [{ type = 'command', command = 'printf hello' }]\n",
			rules:  []string{"AC003"},
		},
		{
			host: report.HostAuto, file: ".grok/hooks/lifecycle.json",
			config: `{"hooks":{"StopCancelled":[{"hooks":[{"type":"command","command":"printf hello"}]}],
				"UnknownEvent":[{"hooks":[{"type":"command","command":"printf ignored"}]}]}}`,
			rules: []string{"AC003"},
		},
	} {
		t.Run(tc.file, func(t *testing.T) {
			root := t.TempDir()
			scenario.WriteFile(t, root, tc.file, tc.config)
			result, err := pluginScan(t, root, tc.host)
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}

			var rules []string
			for _, f := range result.Findings {
				switch f.RuleID {
				case "AC003", "MC001", "MC002", "SC001":
					if f.Location.Path != tc.file || f.Location.StartLine < 1 {
						t.Fatalf("finding has incorrect location: %+v", f.Location)
					}
					if path.Ext(tc.file) == ".toml" && (f.Location.ByteStart != 0 || f.Location.ByteEnd != len(tc.config)) {
						t.Fatalf("TOML evidence should cover the original input: %+v", f.Location)
					}
					rules = append(rules, f.RuleID)
				}
			}
			slices.Sort(rules)
			if !slices.Equal(rules, tc.rules) {
				t.Fatalf("want %v in %s, got %v", tc.rules, tc.file, rules)
			}
		})
	}
}

func TestGrokConfigurationInArchiveUsesRecordedMemberName(t *testing.T) {
	root := t.TempDir()
	scenario.WriteFile(t, root, "workspace.zip", string(zipped(t, map[string]string{
		"project/.grok/config.toml": "[mcp_servers.example]\nurl = 'http://example.invalid/mcp'\n",
		"project/config.toml":       "[mcp_servers.control]\nurl = 'http://example.invalid/control'\n",
	})))

	result, err := pluginScan(t, root, report.HostAuto)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}

	nodes := result.Components.Components
	index := slices.IndexFunc(nodes, func(c report.Component) bool {
		return c.Host == report.HostGrokCLI && c.Kind == "mcp_server" && c.PackagePath == "project/.grok/config.toml"
	})
	if index < 0 {
		t.Fatalf("missing parsed Grok TOML in archive: %+v", nodes)
	}

	var locations []string
	for _, f := range result.Findings {
		if f.RuleID == "MC001" {
			locations = append(locations, f.Location.Path)
		}
	}
	if !slices.Equal(locations, []string{nodes[index].Path}) {
		t.Fatalf("MCP finding escaped its archive member: %v", locations)
	}
}
