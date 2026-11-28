package scout_test

import (
	"errors"
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
			host: report.HostOpenCode, file: "opencode.jsonc",
			config: `{// retain byte evidence
				"mcp": {"servers": {
					"example":{"type":"local","command":["npx","example-mcp@latest"],"environment":{"API_TOKEN":"{env:SCOUT_TEST_TOKEN}"},},
					"remote":{"type":"remote","url":"http://example.invalid/mcp","disabled":true},
				},},
			}`,
			rules: []string{"MC001", "SC001"},
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
