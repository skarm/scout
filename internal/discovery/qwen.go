package discovery

import (
	"os"
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) qwenUser(base string) {
	t.qwenDirectory(base)
	t.geminiContext(path.Join(base, agentconfig.QwenContext))
	t.qwenExtensions(path.Join(base, "extensions"))
}

func (t *tree) qwenDirectory(base string) {
	t.qwenSettings(path.Join(base, artifact.QwenSettings))
	t.geminiContext(path.Join(base, agentconfig.QwenLocalContext))
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "commands"), "command")
	t.instructions(path.Join(base, "rules"), kindRule)
	t.qwenWorkflows(path.Join(base, "workflows"))
	t.qwenSkills(path.Join(base, "skills"))
}

func (t *tree) qwenSkills(root string) {
	before := len(t.b.out.Components)
	for _, e := range t.entries(root) {
		name := path.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(name))
		} else if e.IsDir() {
			t.skill(name, e.Name())
		}
	}

	if len(t.b.out.Components) > before {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) qwenMCP(file string) {
	if n := t.configWithParser(file, false, jsonconfig.ParseWithCommentsAndBOM); n != nil {
		t.servers(n.Get(mcpServersField), file, mcpServersPointer)
	}
}

func (t *tree) qwenLSP(file string) {
	if n := t.config(file, false); n != nil {
		t.serverDeclarations(n, file, "", kindLSPServer, "invalid_lsp_config")
	}
}

func (t *tree) qwenSettings(file string) {
	n := t.configWithParser(file, false, jsonconfig.ParseWithCommentsAndBOM)
	if n == nil {
		return
	}

	t.servers(n.Get(mcpServersField), file, mcpServersPointer)
	t.qwenHooks(n.Get("hooks"), file, "/hooks")
	t.enablementList(n.Get("mcp").Get("allowed"), file, "/mcp/allowed", kindMCPServer, true)
	t.enablementList(n.Get("mcp").Get("excluded"), file, "/mcp/excluded", kindMCPServer, false)
	t.enablementList(n.Get(fieldSkills).Get("disabled"), file, "/skills/disabled", "skill", false)
	t.enablementList(n.Get(fieldSkills).Get(fieldEnabled), file, "/skills/enabled", "skill", true)
	t.enablementList(n.Get("hooks").Get("disabled"), file, "/hooks/disabled", kindHook, false)

	if disabled := n.Get("disableAllHooks"); disabled != nil {
		if disabled.Kind == jsonconfig.KindBool {
			t.setting(kindHook, "*", declaredState(!disabled.Bool), file, "/disableAllHooks")
		} else {
			t.b.issue(codeInvalidEnablement, t.absolute(file))
		}
	}
}

func (t *tree) qwenHooks(n *jsonconfig.Node, file, key string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range n.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if !hookevent.Qwen(event.Key) {
			continue
		}

		if event.Value.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		t.groupedHookItems(event, file, file, key+"/"+pointer(event.Key), agentconfig.QwenHookValid)
	}
}

func (t *tree) qwenExtensions(root string) {
	for _, e := range t.entries(root) {
		dir := path.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(dir))
		} else if e.IsDir() {
			t.qwenExtension(dir)
		}
	}
}

func (t *tree) qwenExtension(dir string) {
	file := path.Join(dir, agentconfig.QwenManifest)

	data := t.read(file, false)
	if data == nil {
		t.qwenPortableExtension(dir)
		return
	}

	n, err := jsonconfig.Parse(t.b.ctx, string(data))
	if err != nil || n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	name, _ := n.Get(fieldName).Text()

	version, _ := n.Get("version").Text()
	if !agentconfig.ValidNamedExtension(name, version) {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	ext := *t
	ext.scope, ext.plugin = "plugin", name
	ext.component("plugin", name, dir, file, "", "unknown")
	ext.b.target(t.absolute(dir))
	ext.servers(n.Get(mcpServersField), file, mcpServersPointer)
	ext.qwenExtensionHooks(dir, file, n.Get("hooks"))
	ext.qwenExtensionLSP(dir, file, n.Get("lspServers"))
	ext.extensionContexts(dir, file, n.Get(agentconfig.ExtensionContextField), agentconfig.QwenContext)
	ext.instructions(path.Join(dir, "rules"), kindRule)
	ext.pluginInstructions(dir, file, "agents", kindAgent, n.Get("agents"))
	ext.pluginInstructions(dir, file, "commands", "command", n.Get("commands"))
	ext.qwenExtensionAssets(dir, file, n)
}

func (t *tree) qwenPortableExtension(dir string) {
	file := path.Join(dir, agentplugins.ManifestFile)

	n := t.config(file, false)
	if version := agentplugins.ManifestVersion(n); version != "" {
		t.portablePlugin(dir, file, n, version)
		t.b.target(t.absolute(dir))
	}
}

func (t *tree) qwenExtensionHooks(dir, file string, n *jsonconfig.Node) {
	if n != nil && n.Kind == jsonconfig.KindObject {
		t.qwenHooks(n, file, "/hooks")
		return
	}

	name, required := path.Join(dir, "hooks/hooks.json"), n != nil
	if required {
		var ok bool

		name, ok = t.qwenPath(dir, file, n)
		if !ok {
			return
		}
	}

	if cfg := t.config(name, required); cfg != nil {
		if hooks := cfg.Get("hooks"); hooks != nil {
			t.qwenHooks(hooks, name, "/hooks")
		} else {
			t.qwenHooks(cfg, name, "")
		}
	}
}

func (t *tree) qwenExtensionLSP(dir, file string, n *jsonconfig.Node) {
	if n == nil {
		return
	}

	if n.Kind == jsonconfig.KindObject {
		t.serverDeclarations(n, file, "/lspServers", kindLSPServer, "invalid_lsp_config")
	} else if name, ok := t.qwenPath(dir, file, n); ok {
		if cfg := t.config(name, true); cfg != nil {
			t.serverDeclarations(cfg, name, "", kindLSPServer, "invalid_lsp_config")
		}
	}
}

func (t *tree) qwenExtensionAssets(dir, file string, n *jsonconfig.Node) {
	t.qwenPaths(dir, file, "skills", n.Get(fieldSkills), func(name string, required bool) {
		if !required || t.requireDirectory(name) {
			t.qwenSkills(name)
		}
	})
	t.qwenPaths(dir, file, "workflows", n.Get("workflows"), func(name string, required bool) {
		if !required || agentconfig.InstructionFile(t.agent, kindWorkflow, name) || t.requireDirectory(name) {
			t.qwenWorkflows(name)
		}
	})

	if channels := n.Get("channels"); channels != nil {
		for _, channel := range channels.Members {
			if !t.b.step(t.absolute(file)) {
				return
			}

			if name, ok := t.qwenPath(dir, file, channel.Value.Get("entry")); ok && t.read(name, true) != nil {
				t.component("channel", channel.Key, name, file, "/channels/"+pointer(channel.Key)+"/entry", "unknown")
			}
		}
	}
}

func (t *tree) qwenPaths(dir, file, fallback string, n *jsonconfig.Node, visit func(string, bool)) {
	if n == nil {
		visit(path.Join(dir, fallback), false)
		return
	}

	paths := []*jsonconfig.Node{n}
	if n.Kind == jsonconfig.KindArray {
		paths = n.Elements
	}

	for _, item := range paths {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if name, ok := t.qwenPath(dir, file, item); ok {
			visit(name, true)
		}
	}
}

func (t *tree) qwenPath(dir, file string, n *jsonconfig.Node) (string, bool) {
	value, ok := n.Text()

	rel, reason := artifactpath.Reference(value, false)
	if !ok || reason != "" || rel == "." {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		return "", false
	}

	return path.Join(dir, rel), true
}

func (t *tree) qwenWorkflows(root string) {
	if agentconfig.InstructionFile(t.agent, kindWorkflow, root) {
		t.qwenWorkflow(root)
		return
	}

	for _, e := range t.entries(root) {
		file := path.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(file))
		} else if e.Type().IsRegular() && agentconfig.InstructionFile(t.agent, kindWorkflow, file) {
			t.qwenWorkflow(file)
		}
	}
}

func (t *tree) qwenWorkflow(file string) {
	if t.read(file, true) != nil {
		t.component(kindWorkflow, strings.TrimSuffix(path.Base(file), path.Ext(file)), file, file, "", "unknown")
	}
}
