package discovery

import (
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const (
	kindAgent = "agent"
	kindRule  = "rule"
	kindTool  = "tool"
)

func (t *tree) cursorUser(base string) {
	t.cursorConfig(base)
	t.plugins(path.Join(base, "plugins/local"))
	t.plugins(path.Join(base, "plugins/cache"))
}

func (t *tree) cursorConfig(base string) {
	t.mcpFile(path.Join(base, "mcp.json"))
	t.nativeHooks(path.Join(base, "hooks.json"))
	t.scripts(path.Join(base, "hooks"), kindHook, false)
	t.skills(path.Join(base, "skills"))
	t.instructions(path.Join(base, "rules"), kindRule)
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "commands"), "command")
}

func (t *tree) copilotUser(base string) {
	t.copilotMCP(path.Join(base, agentconfig.CopilotUserMCP))
	t.copilotHooks(path.Join(base, "hooks"))
	t.copilotSettings(path.Join(base, agentconfig.CopilotSettings))
	t.skills(path.Join(base, "skills"))
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.plugins(path.Join(base, "installed-plugins"))
}

func (t *tree) portableCopilot(base string) {
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "commands"), "command")
	t.instructions(path.Join(base, "rules"), kindRule)
	t.nativeHooks(path.Join(base, "hooks/hooks.json"))
}

func (t *tree) agents(base string) { t.instructions(base, kindAgent) }

func (t *tree) copilotHooks(root string) {
	for _, entry := range t.entries(root) {
		name := path.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(name))
		} else if entry.Type().IsRegular() && path.Ext(name) == ".json" {
			t.nativeHooks(name)
		}
	}
}

func (t *tree) copilotMCP(file string) {
	if n := t.config(file, false); n != nil {
		t.wrappedOrBareServers(n, file, "")
	}
}

func (t *tree) copilotSettings(file string) {
	if n := t.config(file, false); n.Get("hooks") != nil {
		t.hookDeclarations(n, file, "")
	}
}

func (t *tree) wrappedOrBareServers(n *jsonconfig.Node, file, key string) {
	if servers := n.Get(mcpServersField); servers != nil {
		t.servers(servers, file, key+mcpServersPointer)
	} else {
		t.servers(n, file, key)
	}
}

func (t *tree) nativeHooks(file string) {
	if n := t.config(file, false); n != nil {
		t.hookDeclarations(n, file, "")
	}
}

func (t *tree) hookDeclarations(n *jsonconfig.Node, file, key string) {
	hooks := n.Get("hooks")
	if hooks != nil {
		key += "/hooks"
	} else {
		hooks = n
	}

	if hooks.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range hooks.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if event.Value.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		for i, handler := range event.Value.Elements {
			if !t.b.step(t.absolute(file)) {
				return
			}
			// Even host-specific handler kinds whose execution is unmodeled are declarations.
			if handler.Kind != jsonconfig.KindObject {
				t.b.issue(codeInvalidPluginHooks, t.absolute(file))
				continue
			}

			item := key + "/" + pointer(event.Key) + "/" + strconv.Itoa(i)
			t.component(kindHook, event.Key, file, file, item, "unknown")
		}
	}
}

func (t *tree) instructions(root, kind string) {
	t.walk(root, 0, func(dir string) bool {
		for _, entry := range t.entries(dir) {
			file := path.Join(dir, entry.Name())
			if entry.Type().IsRegular() && agentconfig.InstructionFile(t.agent, kind, file) && t.read(file, true) != nil {
				name := strings.TrimSuffix(entry.Name(), path.Ext(entry.Name()))
				if t.agent == report.HostGeminiCLI && kind == "command" {
					name = strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(file, root+"/"), path.Ext(file)), "/", ":")
				}

				t.component(kind, name, file, file, "", "unknown")
			}
		}

		return false
	})
}

func (t *tree) openCodeDirectory(base string) {
	t.openCodeConfig(path.Join(base, agentconfig.OpenCodeConfig))
	t.openCodeConfig(path.Join(base, agentconfig.OpenCodeConfigJSONC))
	t.skills(path.Join(base, "skills"))
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "commands"), "command")
	t.scripts(path.Join(base, "plugins"), "plugin", true)
	t.scripts(path.Join(base, "tools"), kindTool, false)
}

func (t *tree) openCodeConfig(file string) {
	n := t.config(file, false)
	if n == nil {
		return
	}

	servers, key := agentconfig.OpenCodeMCPMap(n)
	t.openCodeServers(file, key, servers)

	for _, field := range []string{"plugins", "plugin"} {
		if list := n.Get(field); list != nil {
			t.openCodePlugins(file, field, list)
		}
	}
}

func (t *tree) openCodeServers(file, key string, n *jsonconfig.Node) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidMCPConfig, t.absolute(file))
		return
	}

	for _, member := range n.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if !agentconfig.OpenCodeServerValid(member.Value) {
			t.b.issue(codeInvalidMCPConfig, t.absolute(file))
			continue
		}

		state := "unknown"
		if enabled, declared := agentconfig.OpenCodeServerEnabled(member.Value); declared {
			state = declaredState(enabled)
		}

		t.component(kindMCPServer, member.Key, file, file, key+"/"+pointer(member.Key), state)
	}
}

func (t *tree) openCodePlugins(file, field string, list *jsonconfig.Node) {
	if list.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	for i, item := range list.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		value, ok := agentconfig.OpenCodePluginValue(item).Text()
		if !ok || value == "" {
			t.b.issue(codeInvalidPluginManifest, t.absolute(file))
			continue
		}

		t.openCodePlugin(file, "/"+field+"/"+strconv.Itoa(i), value)
	}
}

func (t *tree) openCodePlugin(file, key, value string) {
	name, state, target := "configured plugin", "unknown", file
	if disabled, ok := strings.CutPrefix(value, "-"); ok {
		value, state = disabled, "disabled"
	}

	if textmatch.Token(value, 128, "-._@/") && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..") {
		name = value
	}

	if strings.HasPrefix(value, "./") && state != "disabled" {
		if rel, reason := artifactpath.Reference(value, true); reason == "" && rel != "." {
			local := path.Join(path.Dir(file), rel)
			if t.directory(local, false) && t.scriptSource(local) != "" {
				name, target = path.Base(local), local
				t.b.target(t.absolute(target))
			}
		}
	}

	t.component("plugin", name, target, file, key, state)
}

func (t *tree) scripts(dir, kind string, packages bool) {
	for _, entry := range t.entries(dir) {
		file := path.Join(dir, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(file))
			continue
		}

		if kind == kindHook && entry.Type().IsRegular() {
			if t.read(file, true) != nil {
				t.component(kind, entry.Name(), file, file, "", "unknown")
			}

			continue
		}

		if !(packages && entry.IsDir()) && !(entry.Type().IsRegular() && agentconfig.OpenCodeScript(file)) {
			continue
		}

		if source := t.scriptSource(file); source != "" {
			t.component(kind, entry.Name(), file, source, "", "unknown")
			t.b.target(t.absolute(file))
		}
	}
}

func (t *tree) scriptSource(file string) string {
	if agentconfig.OpenCodeScript(file) {
		if t.read(file, false) != nil {
			return file
		}

		return ""
	}

	for _, entry := range []string{"package.json", "index.ts", "index.js"} {
		name := path.Join(file, entry)
		if t.read(name, false) != nil {
			return name
		}
	}

	return ""
}

func (t *tree) pluginConfigs(dir, file string, n *jsonconfig.Node) {
	switch t.agent {
	case report.HostCursor:
		t.cursorPluginConfigs(dir, file, n)
	case report.HostCopilotCLI:
		t.copilotPluginConfigs(dir, file, n)
	case report.HostGrokCLI:
		t.grokPluginConfigs(dir, file, n)
	default:
		t.mcpFile(path.Join(dir, artifact.MCPConfig))
		t.pluginPaths(n.Get(mcpServersField), dir, file, mcpServersPointer, false)
	}
}

func (t *tree) cursorPluginConfigs(dir, file string, n *jsonconfig.Node) {
	if value := n.Get(mcpServersField); value != nil {
		t.pluginPaths(value, dir, file, mcpServersPointer, false)
	} else {
		t.mcpFile(path.Join(dir, "mcp.json"))
	}

	t.pluginHooks(dir, file, n.Get("hooks"), "hooks/hooks.json")

	for _, decl := range []struct{ field, kind string }{{"rules", kindRule}, {"agents", kindAgent}, {"commands", "command"}} {
		t.pluginInstructions(dir, file, decl.field, decl.kind, n.Get(decl.field))
	}
}

func (t *tree) copilotPluginConfigs(dir, file string, n *jsonconfig.Node) {
	for _, name := range []string{artifact.MCPConfig, agentconfig.CopilotProjectMCP} {
		t.copilotMCP(path.Join(dir, name))
	}

	t.pluginPaths(n.Get(mcpServersField), dir, file, mcpServersPointer, false)
	t.pluginHooks(dir, file, n.Get("hooks"), "hooks.json", "hooks/hooks.json")
	t.pluginInstructions(dir, file, "agents", kindAgent, n.Get("agents"))
	t.pluginInstructions(dir, file, "commands", "command", n.Get("commands"))
}

func (t *tree) pluginInstructions(dir, file, defaultDir, kind string, declared *jsonconfig.Node) {
	if declared == nil {
		t.instructions(path.Join(dir, defaultDir), kind)
		return
	}

	paths := []*jsonconfig.Node{declared}
	if declared.Kind == jsonconfig.KindArray {
		paths = declared.Elements
	}

	for _, n := range paths {
		if !t.b.step(t.absolute(file)) {
			return
		}

		rel, reason := artifactpath.Reference(n.String, false)
		if n.Kind != jsonconfig.KindString || reason != "" || rel == "." {
			t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
			continue
		}

		name := path.Join(dir, rel)
		if agentconfig.InstructionFile(t.agent, kind, name) {
			if t.read(name, true) != nil {
				t.component(kind, path.Base(name), name, name, "", "unknown")
			}
		} else if t.requireDirectory(name) {
			t.instructions(name, kind)
		}
	}
}

func (t *tree) pluginHooks(dir, file string, declared *jsonconfig.Node, defaults ...string) {
	if declared != nil {
		switch declared.Kind {
		case jsonconfig.KindObject:
			t.hookDeclarations(declared, file, "/hooks")
		case jsonconfig.KindString:
			if rel, reason := artifactpath.Reference(declared.String, false); reason == "" && rel != "." {
				name := path.Join(dir, rel)
				if cfg := t.config(name, true); cfg != nil {
					t.hookDeclarations(cfg, name, "")
				}
			} else {
				t.b.issue(codeExternalPluginReference, t.absolute(file))
			}
		default:
			t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		}

		return
	}

	for _, name := range defaults {
		t.nativeHooks(path.Join(dir, name))
	}
}
