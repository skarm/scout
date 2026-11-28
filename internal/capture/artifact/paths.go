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
	DeepSeekDirectory          = ".dsh"
	DeepSeekCordis             = "cordis.yml"
	DeepSeekPatch              = "cordis.patch.yml"
	DeepSeekSettings           = "settings.yaml"
	DeepSeekProfiles           = "profiles"
	QwenDirectory              = ".qwen"
	QwenSettings               = "settings.json"
	QwenLSP                    = ".lsp.json"
	QwenSystemDefaults         = "system-defaults.json"
	ZCodeDirectory             = ".zcode"
	ZCodeConfig                = "config.json"
	ZCodeRootConfig            = "zcode.json"
	ZCodeUserConfig            = "cli/" + ZCodeConfig
	ZCodeSharedMCP             = ".agents/mcp.json"
	ZCodePluginManifest        = ".zcode-plugin/plugin.json"
	ZCodeMarketplaceManifest   = ".zcode-plugin/marketplace.json"
	ZCodePluginCache           = "cli/plugins/cache"
	ZCodeInstalledPlugins      = "cli/plugins/installed_plugins.json"
)

func DeepSeekCordisName(name string) bool {
	stem := strings.TrimSuffix(path.Base(name), path.Ext(name))

	return DeepSeekYAMLName(name) && (stem == "cordis" || stem == "cordis.patch" || stem == "cordis.snapshot" ||
		strings.HasSuffix(stem, ".cordis") || strings.HasSuffix(stem, ".cordis.snapshot"))
}

func DeepSeekYAMLName(name string) bool {
	ext := path.Ext(name)
	return ext == ".yml" || ext == ".yaml"
}

func DeepSeekSettingsName(name, host string) bool {
	dir := path.Dir(name)

	return path.Base(name) == DeepSeekSettings &&
		(path.Base(dir) == DeepSeekDirectory || host == report.HostDeepSeekHarness && dir == ".")
}

// DeepSeekSkillRoot identifies a conventional flat or directory skill.
func DeepSeekSkillRoot(name, host string) (string, bool) {
	parts := strings.Split(name, "/")
	for i := range len(parts) - 2 {
		base := parts[i]
		if parts[i+1] != "skills" || base != DeepSeekDirectory && (base != ".agents" || host != report.HostDeepSeekHarness) {
			continue
		}

		if len(parts) == i+3 && path.Ext(parts[i+2]) == ".md" ||
			len(parts) == i+4 && parts[i+3] == SkillManifest && parts[i+2] != ".system" {
			return path.Join(parts[:i+1]...), true
		}
	}

	return "", false
}

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

// QwenSettingsRoot recognizes workspace or system settings, or an explicitly
// selected standalone settings file.
func QwenSettingsRoot(name, host string) (string, bool) {
	dir, file := path.Split(name)

	dir = path.Clean(dir)
	if file == QwenSettings && path.Base(dir) == QwenDirectory {
		return path.Dir(dir), true
	}

	if file != QwenSettings && file != QwenSystemDefaults {
		return "", false
	}

	for _, system := range []string{"/etc/qwen-code", "/Library/Application Support/QwenCode", "/ProgramData/qwen-code"} {
		if strings.HasSuffix("/"+dir, system) {
			return dir, true
		}
	}

	return dir, dir == "." && host == report.HostQwenCode
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
		{ZCodePluginManifest, report.HostZCode},
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
