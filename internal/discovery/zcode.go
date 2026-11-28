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

const zcodeDefaultHooks = "hooks/hooks.json"

func (t *tree) zcodeShared(base string) {
	t.geminiSkills(path.Join(base, "skills"))
	t.instructions(path.Join(base, "commands"), "command")
}

func (t *tree) zcodeAssets(base string) {
	t.geminiSkills(path.Join(base, "skills"))
	t.instructions(path.Join(base, "commands"), "command")
	t.instructions(path.Join(base, "agents"), kindAgent)
}

func (t *tree) zcodeUser(base string) {
	native := t.zcodeConfig(path.Join(base, artifact.ZCodeUserConfig), base)
	if !native {
		// The aliases are relative to the selected OS home, even if .zcode
		// itself is relocated by the operator.
		t.b.open(t.b.options.Home, t.agent, t.scope, false, func(user *tree) {
			user.mcpFile(artifact.ZCodeSharedMCP)
		})
	}

	t.zcodeAssets(base)
	t.geminiContext(path.Join(base, "AGENTS.md"))
	t.zcodeInstalled(path.Join(base, artifact.ZCodeInstalledPlugins))
	t.zcodeCache(path.Join(base, artifact.ZCodePluginCache))
}

func (t *tree) zcodeProject(rootConfig string) {
	rootHasMCP := t.zcodeConfig(rootConfig, ".")

	nativeHasMCP := t.zcodeConfig(path.Join(artifact.ZCodeDirectory, artifact.ZCodeConfig), ".")
	if !rootHasMCP && !nativeHasMCP {
		t.mcpFile(artifact.ZCodeSharedMCP)
	}
}

func (t *tree) zcodeConfig(file, base string) bool {
	n := t.config(file, false)
	if n == nil {
		return false
	}

	mcp := agentconfig.ZCodeMCP(n)
	t.servers(mcp, file, "/mcp/servers")

	if agentconfig.ZCodeRuntimeHooks(n) {
		t.zcodeHooks(n, file, "")
	}

	t.zcodeEnablement(n, file)
	t.zcodeLocalPlugins(n.Get("plugins").Get("dirs"), file, base)

	return agentconfig.ZCodeHasMCP(mcp)
}

func (t *tree) zcodeEnablement(n *jsonconfig.Node, file string) {
	for _, item := range []struct{ section, kind string }{{"plugins", "plugin"}, {"skills", "skill"}, {"hooks", kindHook}} {
		if enabled := n.Get(item.section).Get(fieldEnabled); enabled != nil {
			if enabled.Kind == jsonconfig.KindBool {
				t.setting(item.kind, "*", declaredState(enabled.Bool), file, "/"+item.section+"/enabled")
			} else {
				t.b.issue(codeInvalidEnablement, t.absolute(file))
			}
		}
	}

	for _, member := range n.Get("plugins").GetOrEmpty(fieldEnabledPlugins).Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if member.Value.Kind != jsonconfig.KindBool {
			t.b.issue(codeInvalidEnablement, t.absolute(file))
			continue
		}

		t.setting("plugin", member.Key, declaredState(member.Value.Bool), file, "/plugins/enabledPlugins/"+pointer(member.Key))
	}

	t.enablementList(n.Get("plugins").Get("suppressedBuiltins"), file, "/plugins/suppressedBuiltins", "plugin", false)
}

func (t *tree) zcodeLocalPlugins(dirs *jsonconfig.Node, file, base string) {
	if dirs == nil {
		return
	}

	if dirs.Kind != jsonconfig.KindArray {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		return
	}

	for _, value := range dirs.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		raw, _ := value.Text()

		local := path.Join(base, raw)
		if filepath.IsAbs(raw) {
			relative, err := filepath.Rel(t.absolute(base), raw)
			if err != nil {
				t.b.issue(codeExternalPluginReference, t.absolute(file))
				continue
			}

			raw = filepath.ToSlash(relative)
			local = path.Join(base, raw)
		}

		if rel, reason := artifactpath.Reference(raw, false); reason != "" || rel == "." {
			t.b.issue(codeExternalPluginReference, t.absolute(file))
		} else if t.pluginAt(local) {
			t.b.target(t.absolute(local))
		} else {
			t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		}
	}
}

func (t *tree) zcodeInstalled(file string) {
	root := t.config(file, false)
	if root == nil {
		return
	}

	records := root.Get("plugins")
	if records == nil || records.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	for i, item := range records.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if id, ok := item.Get("id").Text(); ok && id != "" {
			t.component("plugin", id, file, file, "/plugins/"+strconv.Itoa(i), "unknown")
		} else {
			t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		}
	}
}

func (t *tree) zcodeCache(root string) {
	t.walk(root, 0, func(dir string) bool {
		if dir == root {
			return false
		}

		relative := strings.TrimPrefix(dir, root+"/")
		if strings.HasPrefix(path.Base(dir), ".") {
			return true
		}

		if strings.Count(relative, "/") != 2 {
			return false
		}

		if t.pluginAt(dir) {
			t.b.target(t.absolute(dir))
		}

		return true
	})
}

func (t *tree) zcodePluginConfigs(dir, file string, n *jsonconfig.Node) {
	t.wrappedOrBareMCPFile(path.Join(dir, artifact.MCPConfig))
	t.pluginPaths(n.Get(mcpServersField), dir, file, mcpServersPointer, false)
	t.zcodeHookFile(path.Join(dir, zcodeDefaultHooks), false)
	t.pluginConfigPaths(n.Get("hooks"), dir, file, "/hooks", t.zcodeHookFile, t.zcodeHooks)
	t.pluginInstructions(dir, file, "agents", kindAgent, n.Get("agents"))
	t.pluginInstructions(dir, file, "commands", "command", n.Get("commands"))
}

func (t *tree) zcodeHookFile(file string, required bool) {
	if n := t.config(file, required); n != nil {
		t.zcodeHooks(n, file, "")
	}
}

func (t *tree) zcodeHooks(n *jsonconfig.Node, file, key string) {
	for hook := range agentconfig.ZCodeHooks(n) {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if hook.Launch == nil {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		state := "unknown"
		if hook.Disabled {
			state = "disabled"
		} else if enabled := hook.Node.Get("enabled"); enabled != nil && enabled.Kind == jsonconfig.KindBool {
			state = declaredState(enabled.Bool)
		}

		t.component(kindHook, hook.Event, file, file, key+hook.Key, state)
	}
}
