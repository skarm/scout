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
	ClaudeSettings             = "settings.json"
	ClaudeLocalSettings        = "settings.local.json"
	ClaudeProjectSettings      = ".claude/" + ClaudeSettings
	ClaudeProjectLocalSettings = ".claude/" + ClaudeLocalSettings
)

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

// PluginManifestRoot identifies a Claude or Codex manifest by whole path components.
func PluginManifestRoot(name string) (string, bool) {
	for _, manifest := range []string{ClaudePluginManifest, CodexPluginManifest} {
		if name == manifest || strings.HasSuffix(name, "/"+manifest) {
			return path.Dir(path.Dir(name)), true
		}
	}

	return "", false
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
