package discovery

import (
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) kimiLegacyHome(base string) {
	t.kimiTOML(path.Join(base, artifact.KimiConfig))
	t.mcpFile(path.Join(base, artifact.KimiMCP))
	t.kimiSkills(path.Join(base, "skills"))
}

func (t *tree) kimiUser(base string) {
	t.kimiProject(base)
	t.kimiTOML(path.Join(base, artifact.KimiConfig))
	t.geminiContext(path.Join(base, "SYSTEM.md"))
	t.kimiInstalled(base)
}

func (t *tree) kimiProject(base string) {
	t.geminiContext(path.Join(base, "AGENTS.md"))
	t.mcpFile(path.Join(base, artifact.KimiMCP))
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.kimiSkills(path.Join(base, "skills"))
}

func (t *tree) kimiUserShared(base string) {
	t.kimiInstructions(base)
	t.kimiShared(base)
}

func (t *tree) kimiProjectInstructions(file string) {
	t.kimiInstructions(path.Dir(file))
}

func (t *tree) kimiInstructions(base string) {
	upper := path.Join(base, "AGENTS.md")
	if data := t.read(upper, false); len(strings.TrimSpace(string(data))) != 0 {
		t.component(kindRule, path.Base(upper), upper, upper, "", "unknown")
	} else {
		t.geminiContext(path.Join(base, "agents.md"))
	}
}

func (t *tree) kimiShared(base string) {
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.kimiSkills(path.Join(base, "skills"))
}

func (t *tree) kimiSkills(root string) {
	before := len(t.b.out.Components)
	bundles := map[string]bool{}

	t.walk(root, 0, func(dir string) bool {
		if dir != root && strings.HasPrefix(path.Base(dir), ".") {
			return true
		}

		if (dir != root || t.plugin != "") && t.skill(dir, path.Base(dir)) {
			if path.Dir(dir) == root {
				bundles[path.Base(dir)] = true
			}

			return dir != root
		}

		return false
	})

	for _, e := range t.entries(root) {
		if e.Type().IsRegular() && e.Name() != artifact.SkillManifest && path.Ext(e.Name()) == ".md" {
			name := strings.TrimSuffix(e.Name(), ".md")

			file := path.Join(root, e.Name())
			if !bundles[name] && t.read(file, true) != nil {
				t.component("skill", name, file, file, "", "unknown")
			}
		}
	}

	if len(t.b.out.Components) > before {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) kimiTOML(file string) {
	if n := t.config(file, false); n != nil {
		t.kimiHooks(n.Get("hooks"), file)
	}
}

func (t *tree) kimiHooks(hooks *jsonconfig.Node, file string) {
	if hooks == nil {
		return
	}

	if hooks.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for i, item := range hooks.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if agentconfig.KimiHookCommand(item) == nil {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		event, _ := item.Get("event").Text()
		t.component(kindHook, event, file, file, "/hooks/"+strconv.Itoa(i), "unknown")
	}
}

func (t *tree) kimiInstalled(base string) {
	file := path.Join(base, artifact.KimiInstallIndex)

	n := t.config(file, false)
	if n == nil {
		return
	}

	plugins := n.Get("plugins")
	if plugins == nil || plugins.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	for i, record := range plugins.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		t.kimiInstalledPlugin(base, file, record, "/plugins/"+strconv.Itoa(i))
	}
}

func (t *tree) kimiInstalledPlugin(base, file string, record *jsonconfig.Node, key string) {
	id, root, enabled, valid := agentconfig.KimiInstalledRecord(record)
	if !valid {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	t.setting("plugin", id, declaredState(enabled), file, key+"/enabled")
	t.kimiMCPSettings(record.Get("capabilities").Get(mcpServersField), file, key+"/capabilities/"+mcpServersField)

	dir := path.Join(base, artifact.KimiManagedPlugins, id)
	if filepath.IsAbs(root) && filepath.Clean(root) == t.absolute(dir) && t.kimiPlugin(dir, id, enabled) {
		return
	}

	t.component("plugin", id, file, file, key, declaredState(enabled))
	t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
}

func (t *tree) kimiMCPSettings(servers *jsonconfig.Node, file, key string) {
	if servers == nil {
		return
	}

	for _, server := range servers.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if enabled := server.Value.Get(fieldEnabled); enabled != nil && enabled.Kind == jsonconfig.KindBool {
			t.setting(kindMCPServer, server.Key, declaredState(enabled.Bool), file, key+"/"+pointer(server.Key)+"/enabled")
		}
	}
}

func (t *tree) kimiPlugin(dir, id string, enabled bool) bool {
	for _, manifest := range agentconfig.KimiManifests() {
		file := path.Join(dir, manifest)

		data := t.read(file, false)
		if data == nil {
			continue
		}

		n, err := jsonconfig.Parse(t.b.ctx, string(data))

		name, _ := n.Get(fieldName).Text()
		if err != nil || strings.TrimSpace(name) != id {
			t.b.issue(codeInvalidPluginManifest, t.absolute(file))
			return false
		}

		plugin := *t
		plugin.scope, plugin.plugin = "plugin", id
		plugin.component("plugin", id, dir, file, "", declaredState(enabled))
		plugin.b.target(t.absolute(dir))
		plugin.kimiPluginAssets(dir, file, n)

		return true
	}

	return false
}

func (t *tree) kimiPluginAssets(dir, file string, n *jsonconfig.Node) {
	t.servers(n.Get(mcpServersField), file, mcpServersPointer)
	t.kimiHooks(n.Get("hooks"), file)
	t.kimiPluginPaths(dir, file, n.Get("commands"), "command")

	if agents := n.Get("agents"); agents == nil {
		t.instructions(path.Join(dir, "agents"), kindAgent)
	} else {
		t.kimiPluginPaths(dir, file, agents, kindAgent)
	}

	if skills := n.Get(fieldSkills); skills == nil {
		t.skill(dir, path.Base(dir))
	} else {
		t.kimiPluginPaths(dir, file, skills, "skill")
	}

	for _, instruction := range agentconfig.KimiPluginInstructions(n) {
		t.component(kindRule, instruction.Name, file, file, instruction.Key, "unknown")
	}

	if item := n.Get("systemPromptPath"); item != nil {
		if name, ok := t.kimiPluginPath(dir, file, item); ok {
			t.geminiContextFile(name, true)
		}
	}
}

func (t *tree) kimiPluginPaths(dir, file string, n *jsonconfig.Node, kind string) {
	if n == nil {
		return
	}

	items := []*jsonconfig.Node{n}
	if n.Kind == jsonconfig.KindArray {
		items = n.Elements
	}

	for _, item := range items {
		if !t.b.step(t.absolute(file)) {
			return
		}

		name, ok := t.kimiPluginPath(dir, file, item)
		if !ok {
			continue
		}

		switch {
		case kind == "command" && strings.EqualFold(path.Ext(name), ".md"):
			if t.read(name, true) != nil {
				t.component(kind, strings.TrimSuffix(path.Base(name), path.Ext(name)), name, name, "", "unknown")
			}
		case t.requireDirectory(name):
			if kind == "skill" {
				t.kimiSkills(name)
			} else {
				t.instructions(name, kind)
			}
		}
	}
}

func (t *tree) kimiPluginPath(dir, file string, n *jsonconfig.Node) (string, bool) {
	raw, _ := n.Text()
	if rel, reason := artifactpath.Reference(raw, true); strings.HasPrefix(raw, "./") && reason == "" {
		return path.Join(dir, rel), true
	}

	t.b.issue(codeUnsupportedPluginReference, t.absolute(file))

	return "", false
}
