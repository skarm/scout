package discovery

import (
	"context"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	fieldConfig          = "config"
	fieldEnabled         = "enabled"
	fieldMCPServersSnake = "mcp_servers"
	fieldName            = "name"
	fieldPath            = "path"
	fieldPlugins         = "plugins"
	fieldSkills          = "skills"
)

const (
	codeExternalPluginReference    = "external_plugin_reference"
	codeInvalidConfig              = "invalid_config"
	codeInvalidMCPConfig           = "invalid_mcp_config"
	codeInvalidPluginManifest      = "invalid_plugin_manifest"
	codeUnsupportedPluginManifest  = "unsupported_plugin_manifest"
	codeUnsupportedPluginReference = "unsupported_plugin_reference"
)

const codeInvalidEnablement = "invalid_enablement"

func (t *tree) config(name string, required bool) *jsonconfig.Node {
	decode := jsonconfig.Parse
	if strings.EqualFold(path.Ext(name), ".toml") {
		decode = jsonconfig.ParseTOML
	} else if artifact.JSON5ConfigName(path.Base(name)) {
		decode = jsonconfig.ParseJSON5
	} else if strings.EqualFold(path.Ext(name), ".jsonc") {
		decode = jsonconfig.ParseJSONC
	}

	return t.configWithParser(name, required, decode)
}

func (t *tree) configWithParser(name string, required bool, decode func(context.Context, string) (*jsonconfig.Node, error)) *jsonconfig.Node {
	data := t.read(name, required)
	if data == nil {
		return nil
	}

	n, err := decode(t.b.ctx, string(data))
	if err != nil || n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidConfig, t.absolute(name))
		return nil
	}

	return n
}

func (t *tree) servers(n *jsonconfig.Node, source, key string) {
	t.serverDeclarations(n, source, key, kindMCPServer, codeInvalidMCPConfig)
}

func (t *tree) serverDeclarations(n *jsonconfig.Node, source, key, kind, invalid string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue(invalid, t.absolute(source))
		return
	}

	for _, entry := range n.Members {
		if !t.b.step(t.absolute(source)) {
			return
		}

		if t.agent == report.HostCopilotCLI && key == "" && entry.Key == "$schema" && entry.Value.Kind == jsonconfig.KindString {
			continue
		}

		if entry.Value.Kind != jsonconfig.KindObject {
			t.b.issue(invalid, t.absolute(source))
			continue
		}

		state := "unknown"

		if enabled := entry.Value.Get(fieldEnabled); enabled != nil {
			if enabled.Kind == jsonconfig.KindBool {
				state = declaredState(enabled.Bool)
			} else {
				t.b.issue(codeInvalidEnablement, t.absolute(source))
			}
		}

		t.component(kind, entry.Key, source, source, key+"/"+pointer(entry.Key), state)
	}
}

func (t *tree) mcpFile(name string) {
	if n := t.config(name, false); n != nil {
		t.servers(n.Get(mcpServersField), name, mcpServersPointer)
	}
}

func (t *tree) codexConfig(name string) {
	n := t.config(name, false)
	if n == nil {
		return
	}

	t.servers(n.Get(fieldMCPServersSnake), name, "/"+fieldMCPServersSnake)

	if plugins := n.Get(fieldPlugins); plugins != nil && plugins.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidEnablement, t.absolute(name))
	}

	for _, entry := range n.GetOrEmpty(fieldPlugins).Members {
		enabled := entry.Value.Get(fieldEnabled)
		if entry.Value.Kind != jsonconfig.KindObject || enabled != nil && enabled.Kind != jsonconfig.KindBool {
			t.b.issue(codeInvalidEnablement, t.absolute(name))
		} else if enabled != nil {
			t.setting("plugin", entry.Key, declaredState(enabled.Bool), name, "/plugins/"+pointer(entry.Key)+"/enabled")
		}
	}

	skills := n.Get(fieldSkills)

	config := skills.Get(fieldConfig)
	if skills != nil && skills.Kind != jsonconfig.KindObject || config != nil && config.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidEnablement, t.absolute(name))
	}

	for i, entry := range skills.GetOrEmpty(fieldConfig).Elements {
		enabled := entry.Get(fieldEnabled)

		value, ok := entry.Get(fieldPath).Text()
		if ok && enabled != nil && enabled.Kind == jsonconfig.KindBool {
			t.setting("skill", value, declaredState(enabled.Bool), name, "/skills/config/"+strconv.Itoa(i)+"/enabled")
		} else {
			t.b.issue(codeInvalidEnablement, t.absolute(name))
		}
	}
}

func (t *tree) plugins(root string) {
	// Scan every nonempty known cache, even when a package has no manifest or
	// only components outside the metadata inventory's skill/MCP subset.
	if t.walk(root, 0, func(dir string) bool { return t.pluginAt(dir) || t.manifestlessPluginAt(dir, root) }) {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) pluginAt(dir string) bool {
	var plain *jsonconfig.Node

	for i, relative := range pluginManifests(t.agent) {
		file := path.Join(dir, relative)

		n := plain
		if relative != agentplugins.ManifestFile || i == 0 {
			n = t.config(file, false)
		}

		if n == nil {
			continue
		}

		if relative == agentplugins.ManifestFile && i == 0 {
			if v := agentplugins.ManifestVersion(n); v != "" {
				t.portablePlugin(dir, file, n, v)
				return true
			}

			plain = n

			continue
		}

		if t.agent == report.HostGrokCLI && relative == artifact.GrokPluginManifest && agentconfig.GrokMarketplaceIndex(n) {
			continue
		}

		name, ok := n.Get(fieldName).Text()
		if !ok || name == "" {
			t.b.issue(codeInvalidPluginManifest, t.absolute(file))
			return true
		}

		plugin := *t
		plugin.scope, plugin.plugin = "plugin", name
		plugin.component("plugin", name, dir, file, "", "unknown")
		plugin.pluginSkills(dir, n.Get(fieldSkills))

		plugin.pluginPaths(n.Get(fieldSkills), dir, file, "/"+fieldSkills, true)
		plugin.pluginConfigs(dir, file, n)

		return true
	}

	return false
}

func pluginManifests(host string) []string {
	switch host {
	case report.HostClaudeCode:
		return []string{artifact.ClaudePluginManifest}
	case report.HostCursor:
		return []string{agentplugins.ManifestFile, artifact.CursorPluginManifest}
	case report.HostCopilotCLI:
		return append([]string{agentplugins.ManifestFile}, agentconfig.CopilotLegacyManifests()...)
	case report.HostGrokCLI:
		return append([]string{agentplugins.ManifestFile}, agentconfig.GrokLegacyManifests()...)
	case report.HostZCode:
		return agentconfig.ZCodeManifests()
	case report.HostOpenCode, report.HostGeminiCLI, report.HostOpenClaw, report.HostDeepSeekHarness:
		return nil
	default:
		return []string{agentplugins.ManifestFile, artifact.CodexPluginManifest, artifact.ClaudePluginManifest}
	}
}

func (t *tree) pluginSkills(dir string, declared *jsonconfig.Node) {
	root := path.Join(dir, "skills")
	if t.agent == report.HostZCode {
		t.geminiSkills(root)
		return
	}

	if (t.agent == report.HostClaudeCode || t.agent == report.HostCopilotCLI) && declared == nil && !t.directory(root, false) {
		t.skill(dir, t.plugin)
		return
	}

	t.skills(root)
}

func (t *tree) manifestlessPluginAt(dir, root string) bool {
	if t.agent != report.HostClaudeCode || dir == root {
		return false
	}

	relative := strings.TrimPrefix(dir, root+"/")
	if path.Base(root) == "cache" && strings.Count(relative, "/") != 2 {
		return false
	}

	// A malformed manifest already created a gap; do not reinterpret it as an
	// absent optional manifest or infer packages at arbitrary cache depths.
	if _, present := t.b.sources[t.absolute(path.Join(dir, artifact.ClaudePluginManifest))]; present {
		return false
	}

	name := path.Base(dir)
	if path.Base(root) == "cache" {
		name = path.Base(path.Dir(dir))
	}

	plugin := *t
	plugin.scope, plugin.plugin = "plugin", name
	before := len(t.b.out.Components)

	plugin.pluginSkills(dir, nil)
	plugin.mcpFile(path.Join(dir, artifact.MCPConfig))

	if len(t.b.out.Components) == before {
		return false
	}

	// Without plugin.json the directory provides the candidate name, while an
	// actually captured default component provides source provenance.
	t.b.add(Component{
		Agent: t.agent, Kind: "plugin", Name: name, Scope: "plugin",
		Path: t.absolute(dir), Source: t.b.out.Components[before].Source,
		State: "unknown", Plugin: name, Project: t.project,
	})

	return true
}

func (t *tree) pluginPaths(n *jsonconfig.Node, dir, source, key string, skills bool) {
	if n == nil {
		return
	}

	switch n.Kind {
	case jsonconfig.KindArray:
		for i, item := range n.Elements {
			t.pluginPaths(item, dir, source, key+"/"+strconv.Itoa(i), skills)
		}
	case jsonconfig.KindObject:
		if skills {
			t.b.issue(codeUnsupportedPluginReference, t.absolute(source))
		} else if t.agent == report.HostCursor || t.agent == report.HostCopilotCLI || t.agent == report.HostGrokCLI || t.agent == report.HostZCode {
			t.wrappedOrBareServers(n, source, key)
		} else {
			t.servers(n, source, key)
		}
	case jsonconfig.KindString:
		t.pluginPath(n.String, dir, source, skills)
	default:
		t.b.issue(codeUnsupportedPluginReference, t.absolute(source))
	}
}

func (t *tree) pluginPath(value, dir, source string, skills bool) {
	if (t.agent == report.HostCursor || t.agent == report.HostCopilotCLI || t.agent == report.HostGrokCLI || t.agent == report.HostZCode) && !strings.HasPrefix(value, "./") {
		rel, reason := artifactpath.Reference(value, false)
		if reason != "" {
			t.b.issue(codeExternalPluginReference, t.absolute(source))
			return
		}

		value = "./" + rel
	}

	if value != "." && !strings.HasPrefix(value, "./") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) ||
		slicesContainParent(value) {
		t.b.issue(codeExternalPluginReference, t.absolute(source))
		return
	}

	name := path.Join(dir, value)
	if skills {
		if t.requireDirectory(name) {
			if t.agent == report.HostZCode {
				t.geminiSkills(name)
			} else {
				t.skills(name)
			}
		}
	} else if path.Ext(name) == ".json" {
		if n := t.config(name, true); n != nil {
			if wrapped := n.Get(mcpServersField); wrapped != nil {
				t.servers(wrapped, name, mcpServersPointer)
			} else {
				t.servers(n, name, "")
			}
		}
	} else {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(source))
	}
}

func slicesContainParent(name string) bool {
	for part := range strings.SplitSeq(name, "/") {
		if part == ".." {
			return true
		}
	}

	return false
}

func pointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func declaredState(value bool) string {
	if value {
		return "enabled"
	}

	return "disabled"
}
