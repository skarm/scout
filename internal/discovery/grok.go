package discovery

import (
	"os"
	"path"
	"strconv"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	kindLSPServer = "lsp-server"
	kindWorkflow  = "workflow"
	grokLSPField  = "lspServers"
)

func (t *tree) grokUser(base string) {
	t.grokDirectory(base)
	t.grokTOML(path.Join(base, artifact.GrokConfig))
	t.grokTOML(path.Join(base, artifact.GrokManagedConfig))
	t.grokTOML(path.Join(base, artifact.GrokRequirements))
}

func (t *tree) grokProject(base string) {
	t.grokDirectory(base)
	t.grokTOML(path.Join(base, artifact.GrokConfig))
}

func (t *tree) grokDirectory(base string) {
	t.skills(path.Join(base, "skills"))
	t.commands(path.Join(base, "commands"))
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "workflows"), kindWorkflow)
	t.grokLSPFile(path.Join(base, artifact.GrokLSP), false)
	t.grokHookDirectory(path.Join(base, "hooks"))
	t.grokPlugins(path.Join(base, "plugins"))
}

func (t *tree) grokTOML(file string) {
	n := t.config(file, false)
	if n == nil {
		return
	}

	t.servers(n.Get(fieldMCPServersSnake), file, "/"+fieldMCPServersSnake)
	t.enablementList(n.Get(fieldPlugins).Get(fieldEnabled), file, "/plugins/enabled", "plugin", true)
	t.enablementList(n.Get(fieldPlugins).Get("disabled"), file, "/plugins/disabled", "plugin", false)

	// Grok does not load hooks declared inside project config.toml.
	if t.scope != "project" && n.Get("hooks") != nil {
		t.grokHookGroups(n.Get("hooks"), file, "/hooks")
	}
}

func (t *tree) grokHookDirectory(dir string) {
	for _, entry := range t.entries(dir) {
		file := path.Join(dir, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(file))
		} else if entry.Type().IsRegular() && path.Ext(file) == ".json" {
			t.grokHookFile(file, true)
		}
	}
}

func (t *tree) grokHookFile(file string, required bool) {
	if n := t.config(file, required); n != nil {
		t.grokHooks(n, file, "")
	}
}

func (t *tree) grokHooks(n *jsonconfig.Node, file, key string) {
	if hooks := n.Get("hooks"); hooks != nil {
		t.grokHookGroups(hooks, file, key+"/hooks")
	} else {
		t.grokHookGroups(n, file, key)
	}
}

func (t *tree) grokHookGroups(n *jsonconfig.Node, file, key string) {
	if n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range n.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if !hookevent.Grok(event.Key) {
			continue
		}

		if event.Value.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		t.groupedHookItems(event, file, key+"/"+pointer(event.Key), func(n *jsonconfig.Node) bool { return agentconfig.GrokHookTarget(n) != nil })
	}
}

func (t *tree) groupedHookItems(event jsonconfig.Member, file, key string, valid func(*jsonconfig.Node) bool) {
	for i, group := range event.Value.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		handlers := group.Get("hooks")
		if handlers == nil || handlers.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		for j, handler := range handlers.Elements {
			if !t.b.step(t.absolute(file)) {
				return
			}

			if !valid(handler) {
				t.b.issue(codeInvalidPluginHooks, t.absolute(file))
				continue
			}

			item := key + "/" + strconv.Itoa(i) + "/hooks/" + strconv.Itoa(j)
			t.component(kindHook, event.Key, file, file, item, "unknown")
		}
	}
}

func (t *tree) grokPlugins(root string) {
	t.walk(root, 0, func(dir string) bool {
		// A marketplace checkout holds available packages. Inventory installed
		// packages separately from files in that checkout.
		if path.Dir(dir) == root && path.Base(dir) == "marketplaces" {
			return true
		}

		if dir != root && (t.pluginAt(dir) || t.grokManifestless(dir, root)) {
			t.b.target(t.absolute(dir))
			return true
		}

		return false
	})
}

func (t *tree) grokManifestless(dir, root string) bool {
	if path.Dir(dir) != root {
		return false
	}

	// A malformed captured manifest must not be reinterpreted as absent.
	for _, manifest := range agentconfig.GrokLegacyManifests() {
		if _, found := t.b.sources[t.absolute(path.Join(dir, manifest))]; found {
			return false
		}
	}

	plugin := *t
	plugin.scope, plugin.plugin = "plugin", path.Base(dir)
	before := len(t.b.out.Components)

	plugin.skills(path.Join(dir, "skills"))
	plugin.grokPluginConfigs(dir, "", nil)

	if len(t.b.out.Components) == before {
		return false
	}

	t.b.add(Component{
		Agent: t.agent, Kind: "plugin", Name: plugin.plugin, Scope: "plugin", Path: t.absolute(dir),
		Source: t.b.out.Components[before].Source, State: "unknown", Plugin: plugin.plugin, Project: t.project,
	})

	return true
}

func (t *tree) grokPluginConfigs(dir, file string, n *jsonconfig.Node) {
	t.wrappedOrBareMCPFile(path.Join(dir, artifact.MCPConfig))
	t.pluginPaths(n.Get(mcpServersField), dir, file, mcpServersPointer, false)
	t.grokLSPFile(path.Join(dir, ".lsp.json"), false)
	t.pluginConfigPaths(n.Get(grokLSPField), dir, file, "/"+grokLSPField, t.grokLSPFile, t.grokLSP)

	t.grokHookFile(path.Join(dir, "hooks/hooks.json"), false)
	t.pluginConfigPaths(n.Get("hooks"), dir, file, "/hooks", t.grokHookFile, t.grokHooks)
	t.pluginInstructions(dir, file, "agents", kindAgent, n.Get("agents"))
	t.pluginInstructions(dir, file, "commands", "command", n.Get("commands"))
}

func (t *tree) wrappedOrBareMCPFile(file string) {
	if n := t.config(file, false); n != nil {
		t.wrappedOrBareServers(n, file, "")
	}
}

func (t *tree) grokLSPFile(file string, required bool) {
	if n := t.config(file, required); n != nil {
		t.grokLSP(n, file, "")
	}
}

func (t *tree) grokLSP(n *jsonconfig.Node, file, key string) {
	if servers := n.Get(grokLSPField); servers != nil {
		n, key = servers, key+"/"+grokLSPField
	}

	t.serverDeclarations(n, file, key, kindLSPServer, "invalid_lsp_config")
}

func (t *tree) pluginConfigPaths(n *jsonconfig.Node, dir, file, key string, load func(string, bool), inspect func(*jsonconfig.Node, string, string)) {
	if n == nil {
		return
	}

	if n.Kind == jsonconfig.KindObject {
		inspect(n, file, key)
		return
	}

	if n.Kind == jsonconfig.KindArray {
		for i, item := range n.Elements {
			if !t.b.step(t.absolute(file)) {
				return
			}

			if item.Kind == jsonconfig.KindArray {
				t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
				continue
			}

			t.pluginConfigPaths(item, dir, file, key+"/"+strconv.Itoa(i), load, inspect)
		}

		return
	}

	raw, _ := n.Text()

	rel, reason := artifactpath.Reference(raw, false)
	if reason != "" || rel == "." {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		return
	}

	load(path.Join(dir, rel), true)
}
