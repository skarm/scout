package discovery

import (
	"os"
	"path"
	"strconv"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	kindHook                   = "hook"
	codeInvalidPluginHooks     = "invalid_plugin_hooks"
	codePortableManifestFields = "portable_plugin_manifest_fields_ignored"
)

func (t *tree) portablePlugin(dir, file string, manifest *jsonconfig.Node, version agentplugins.Version) {
	if version == agentplugins.Unsupported {
		t.b.issue(codeUnsupportedPluginManifest, t.absolute(file))
		return
	}

	metadata := version.ReadManifest(manifest)
	if !metadata.Valid {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	if metadata.IgnoredFields {
		t.b.issue(codePortableManifestFields, t.absolute(file))
	}

	plugin := *t
	plugin.scope, plugin.plugin = "plugin", metadata.Name
	plugin.component("plugin", metadata.Name, dir, file, "", "unknown")

	for _, entry := range plugin.entries(path.Join(dir, agentplugins.SkillsDir)) {
		base := path.Join(dir, agentplugins.SkillsDir, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			plugin.b.issue(codeSymlinkRefused, plugin.absolute(base))
		} else if entry.IsDir() {
			plugin.skill(base, entry.Name())
		}
	}

	plugin.portableMCP(path.Join(dir, agentplugins.MCPFile), version)

	if version == agentplugins.V1_1 && t.agent != report.HostQwenCode {
		plugin.portableHooks(dir, version)
	}

	if t.agent == report.HostCopilotCLI && version == agentplugins.V1_0 {
		plugin.portableCopilot(path.Join(dir, agentconfig.CopilotExtension))
	}

	if t.agent == report.HostCodex {
		plugin.portableCodexHooks(dir, file, manifest)
	}
}

func (t *tree) portableCodexHooks(dir, file string, manifest *jsonconfig.Node) {
	settings := agentplugins.OpenAISettings(manifest)
	key := "/extensions/com.openai/hooks"

	if settings == nil {
		file = path.Join(dir, artifact.CodexPluginManifest)
		settings = t.config(file, false)
		key = "/hooks"
	}

	inspect := func(n *jsonconfig.Node, source, pointer string) {
		if wrapped := n.Get("hooks"); wrapped != nil {
			n, pointer = wrapped, pointer+"/hooks"
		}

		t.claudeHookGroups(n, dir, source, pointer)
	}
	load := func(source string, required bool) {
		if n := t.config(source, required); n != nil {
			inspect(n, source, "")
		}
	}

	if hooks := settings.Get("hooks"); hooks != nil {
		t.pluginConfigPaths(hooks, dir, file, key, load, inspect)
	} else {
		load(path.Join(dir, "hooks/hooks.json"), false)
	}
}

func (t *tree) portableMCP(file string, version agentplugins.Version) {
	n := t.config(file, false)
	if n == nil {
		return
	}

	servers := version.MCPServers(n)
	if servers == nil {
		t.b.issue(codeInvalidMCPConfig, t.absolute(file))
		return
	}

	for _, member := range servers.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if !agentplugins.ValidMCPServer(member.Value) {
			t.b.issue(codeInvalidMCPConfig, t.absolute(file))
			continue
		}

		if t.agent == report.HostQwenCode && agentconfig.QwenPortableSSE(member.Value) {
			continue
		}

		t.component(kindMCPServer, member.Key, file, file, mcpServersPointer+"/"+pointer(member.Key), "unknown")
	}
}

func (t *tree) portableHooks(dir string, version agentplugins.Version) {
	file := path.Join(dir, agentplugins.HooksFile)

	n := t.config(file, false)
	if n == nil {
		return
	}

	hooks := version.Hooks(n)
	if hooks == nil {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range hooks.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if !agentplugins.ValidHookEvent(event) {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		for i, handler := range event.Value.Elements {
			if !t.b.step(t.absolute(file)) {
				return
			}

			if !agentplugins.ValidHook(handler) {
				t.b.issue(codeInvalidPluginHooks, t.absolute(file))
				continue
			}

			key := "/" + agentplugins.HooksField + "/" + pointer(event.Key) + "/" + strconv.Itoa(i)
			t.component(kindHook, event.Key, dir, file, key, "unknown")
		}
	}
}
