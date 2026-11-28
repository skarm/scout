package artifact

import (
	"net/url"
	"path"
	"strings"

	"github.com/skarm/scout/report"
)

// Names shared by discovery, capture and analysis of host declarations.
const (
	SkillManifest = "SKILL.md"
	// MCPConfig is the conventional project and plugin MCP configuration filename.
	MCPConfig                  = ".mcp.json"
	ClaudePluginManifest       = ".claude-plugin/plugin.json"
	CodexPluginManifest        = ".codex-plugin/plugin.json"
	CursorPluginManifest       = ".cursor-plugin/plugin.json"
	CopilotPluginManifest      = ".plugin/plugin.json"
	CopilotGitHubManifest      = ".github/plugin/plugin.json"
	ClaudeSettings             = "settings.json"
	ClaudeLocalSettings        = "settings.local.json"
	ClaudeProjectSettings      = ".claude/" + ClaudeSettings
	ClaudeProjectLocalSettings = ".claude/" + ClaudeLocalSettings
	GeminiDirectory            = ".gemini"
	GeminiSettings             = "settings.json"
	GeminiSystemDefaults       = "system-defaults.json"
	OpenClawDirectory          = ".openclaw"
	OpenClawConfig             = "openclaw.json"
	OpenClawManifest           = "openclaw.plugin.json"
	OpenClawHookManifest       = "HOOK.md"
	GrokDirectory              = ".grok"
	GrokConfig                 = "config.toml"
	GrokManagedConfig          = "managed_config.toml"
	GrokRequirements           = "requirements.toml"
	GrokPluginManifest         = ".grok-plugin/plugin.json"
	GrokMarketplaceManifest    = ".grok-plugin/marketplace.json"
	GrokLSP                    = "lsp.json"
)

// GrokTOMLRoot recognizes named Grok config files and explicitly interpreted standalone files.
func GrokTOMLRoot(name, host string) (string, bool) {
	dir, base := path.Dir(name), path.Base(name)
	if base != GrokConfig && base != GrokManagedConfig && base != GrokRequirements {
		return "", false
	}

	if path.Base(dir) == GrokDirectory {
		return path.Dir(dir), true
	}

	return dir, dir == "." && host == report.HostGrokCLI || path.Base(dir) == "grok" && path.Base(path.Dir(dir)) == "etc"
}

// JSON5ConfigName identifies explicitly named JSON5 configuration files.
func JSON5ConfigName(name string) bool {
	return name == OpenClawConfig || name == OpenClawManifest || strings.EqualFold(path.Ext(name), ".json5")
}

// GeminiSettingsRoot recognizes an unambiguous workspace path or a standalone
// settings file interpreted with an explicit Gemini CLI profile.
func GeminiSettingsRoot(name, host string) (string, bool) {
	dir, file := path.Dir(name), path.Base(name)
	if file == GeminiSettings && path.Base(dir) == GeminiDirectory {
		return path.Dir(dir), true
	}

	return dir, dir == "." && host == report.HostGeminiCLI && (file == GeminiSettings || file == GeminiSystemDefaults)
}

// RootNamespace identifies top-level captures independently of archive parents.
const RootNamespace = "snapshot"

const escapedRootNamespace = "./" + RootNamespace

// ArchiveNamespace identifies an archive namespace without colliding with the
// root sentinel. Captured paths cannot start with a dot path component.
func ArchiveNamespace(parent string) string {
	if parent == RootNamespace {
		return escapedRootNamespace
	}

	return parent
}

// ArchiveParentPath recovers the captured parent of an archive namespace.
func ArchiveParentPath(namespace string) (string, bool) {
	switch namespace {
	case RootNamespace:
		return "", false
	case escapedRootNamespace:
		return RootNamespace, true
	default:
		return namespace, true
	}
}

// PluginManifestRoot identifies a native manifest by whole path components.
func PluginManifestRoot(name string) (string, bool) {
	root, host := NativePluginManifest(name)
	return root, host != ""
}

// NativePluginManifest identifies an unambiguous host-specific manifest path.
func NativePluginManifest(name string) (root, host string) {
	for _, candidate := range []struct{ file, host string }{
		{ClaudePluginManifest, report.HostClaudeCode},
		{CodexPluginManifest, report.HostCodex},
		{CursorPluginManifest, report.HostCursor},
		{CopilotPluginManifest, report.HostCopilotCLI},
		{CopilotGitHubManifest, report.HostCopilotCLI},
		{GrokPluginManifest, report.HostGrokCLI},
	} {
		if name == candidate.file {
			return ".", candidate.host
		}

		if root, ok := strings.CutSuffix(name, "/"+candidate.file); ok {
			return root, candidate.host
		}
	}

	return "", ""
}

// BaseName returns the captured name, decoding the URI representation of an extracted object.
func (f File) BaseName() string {
	name := f.meta.Path
	if strings.HasPrefix(name, report.ObjectPathPrefix) {
		if decoded, err := url.PathUnescape(name); err == nil {
			name = decoded
		}
	}

	return path.Base(name)
}
