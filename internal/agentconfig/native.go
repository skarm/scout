// Package agentconfig describes captured native agent declarations. It does not
// load plugins, run hooks, resolve credentials, or connect to MCP servers.
package agentconfig

import (
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	CursorDirectory             = ".cursor"
	CopilotDirectory            = ".copilot"
	OpenCodeDirectory           = ".opencode"
	OpenCodeConfig              = "opencode.json"
	OpenCodeConfigJSONC         = "opencode.jsonc"
	CopilotProjectMCP           = ".github/mcp.json"
	CopilotUserMCP              = "mcp-config.json"
	CopilotProjectHooks         = ".github/hooks"
	CopilotSettings             = "settings.json"
	CopilotProjectSettings      = ".github/copilot/settings.json"
	CopilotProjectLocalSettings = ".github/copilot/settings.local.json"
	CopilotExtension            = "com.github.copilot"
	CursorProjectMCP            = ".cursor/mcp.json"
	CursorProjectHooks          = ".cursor/hooks.json"
)

// CopilotLegacyManifests is the loader's manifest precedence after Agent Plugins.
func CopilotLegacyManifests() []string {
	return []string{artifact.CopilotPluginManifest, agentplugins.ManifestFile, artifact.CopilotGitHubManifest, artifact.ClaudePluginManifest}
}

func OpenCodeConfigFile(name string) bool {
	return name == OpenCodeConfig || name == OpenCodeConfigJSONC
}

func InstructionFile(host, kind, name string) bool {
	ext := strings.ToLower(path.Ext(name))
	if host == report.HostCursor {
		return slices.Contains([]string{".md", ".mdc", ".markdown"}, ext) || kind == "command" && ext == ".txt"
	}

	if host == report.HostGeminiCLI && (kind == "command" || kind == "rule") {
		return ext == ".toml"
	}

	if host == report.HostGrokCLI && kind == "workflow" {
		return ext == ".rhai"
	}

	return ext == ".md"
}

func OpenCodeScript(name string) bool {
	return slices.Contains([]string{".js", ".ts"}, path.Ext(name))
}

// OpenCodePluginValue retains the source span of a configured plugin name.
func OpenCodePluginValue(n *jsonconfig.Node) *jsonconfig.Node {
	switch n.Kind {
	case jsonconfig.KindString:
		return n
	case jsonconfig.KindObject:
		return n.Get("package")
	case jsonconfig.KindArray:
		if len(n.Elements) == 2 && n.Elements[1].Kind == jsonconfig.KindObject {
			return n.Elements[0]
		}
	}

	return nil
}

// OpenCodeMCPMap recognizes both the v2 mcp.servers envelope and v1's flat map.
func OpenCodeMCPMap(root *jsonconfig.Node) (*jsonconfig.Node, string) {
	mcp := root.Get("mcp")
	if servers := mcp.Get("servers"); servers != nil && !OpenCodeServerValid(servers) {
		return servers, "/mcp/servers"
	}

	return mcp, "/mcp"
}

func OpenCodeServerEnabled(n *jsonconfig.Node) (enabled, declared bool) {
	if value := n.Get("disabled"); value != nil && value.Kind == jsonconfig.KindBool {
		return !value.Bool, true
	}

	if value := n.Get("enabled"); value != nil && value.Kind == jsonconfig.KindBool {
		return value.Bool, true
	}

	return false, false
}

// OpenCodeServerValid checks the native MCP union, including a disabled-only override.
func OpenCodeServerValid(n *jsonconfig.Node) bool {
	if n == nil || n.Kind != jsonconfig.KindObject {
		return false
	}

	enabled := n.Get("enabled")

	disabled := n.Get("disabled")
	if enabled != nil && enabled.Kind != jsonconfig.KindBool || disabled != nil && disabled.Kind != jsonconfig.KindBool {
		return false
	}

	typ, _ := n.Get("type").Text()
	switch typ {
	case "local":
		command := n.Get("command")
		if command == nil || command.Kind != jsonconfig.KindArray || len(command.Elements) == 0 || command.Elements[0].String == "" {
			return false
		}

		return !slices.ContainsFunc(command.Elements, func(word *jsonconfig.Node) bool { return word.Kind != jsonconfig.KindString }) && n.Get("url") == nil
	case "remote":
		url, ok := n.Get("url").Text()
		return ok && url != "" && n.Get("command") == nil
	default:
		return len(n.Members) == 1 && enabled != nil
	}
}

// HookRun is a passive reference to a native hook launch field.
type HookRun struct {
	Field string
	Value *jsonconfig.Node
}

// HookRuns returns configured platform launches without choosing a platform.
func HookRuns(host string, handler *jsonconfig.Node) []HookRun {
	if handler.Kind != jsonconfig.KindObject {
		return nil
	}

	if host == report.HostCursor {
		if command, ok := handler.Get("command").Text(); ok && command != "" {
			return []HookRun{{"command", handler.Get("command")}}
		}

		return nil
	}

	if typ := handler.Get("type"); typ != nil && typ.String != "command" {
		return nil
	}

	if direct := handler.Get("exec"); direct != nil {
		if direct.String == "" || handler.Get("command") != nil || handler.Get("bash") != nil || handler.Get("powershell") != nil {
			return nil
		}

		return []HookRun{{"exec", direct}}
	}

	var result []HookRun

	for _, field := range []string{"bash", "powershell", "command"} {
		if field == "command" && handler.Get("bash") != nil && handler.Get("powershell") != nil {
			continue
		}

		if n := handler.Get(field); n != nil {
			if n.Kind != jsonconfig.KindString || n.String == "" {
				return nil
			}

			result = append(result, HookRun{field, n})
		}
	}

	return result
}

// OpenCodeForMCPChecks adapts argv and environment fields to the common passive
// checks while preserving the original physical spans and leaving the tree immutable.
func OpenCodeForMCPChecks(n *jsonconfig.Node) *jsonconfig.Node {
	if n.Kind != jsonconfig.KindObject {
		return n
	}

	result := *n

	result.Members = make([]jsonconfig.Member, 0, len(n.Members)+1)
	for _, m := range n.Members {
		switch m.Key {
		case "env", "args":
			continue
		case "environment":
			m.Key = "env"
		case "command":
			if m.Value.Kind == jsonconfig.KindArray && len(m.Value.Elements) != 0 {
				first := m.Value.Elements[0]
				args := *m.Value
				args.Elements = args.Elements[1:]
				result.Members = append(result.Members, jsonconfig.Member{Key: "args", KeySpan: m.KeySpan, Value: &args})
				m.Value = first
			}
		}

		result.Members = append(result.Members, m)
	}

	return &result
}
