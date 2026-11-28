package discovery

import (
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) geminiUser(base string) {
	t.geminiDirectory(base)
	t.geminiContext(path.Join(base, agentconfig.GeminiContext))
	t.geminiExtensions(path.Join(base, "extensions"))
}

func (t *tree) geminiDirectory(base string) {
	t.geminiSettings(path.Join(base, artifact.GeminiSettings))
	t.geminiSkills(path.Join(base, "skills"))
	t.geminiInstructions(base)
}

func (t *tree) geminiInstructions(base string) {
	t.instructions(path.Join(base, "agents"), kindAgent)
	t.instructions(path.Join(base, "commands"), "command")
	t.geminiPolicies(path.Join(base, "policies"))
}

func (t *tree) geminiPolicies(root string) { t.instructions(root, kindRule) }

func (t *tree) geminiSkills(root string) {
	before := len(t.b.out.Components)
	if !t.skill(root, path.Base(root)) {
		for _, e := range t.entries(root) {
			name := path.Join(root, e.Name())
			if e.Type()&os.ModeSymlink != 0 {
				t.b.issue(codeSymlinkRefused, t.absolute(name))
			} else if e.IsDir() {
				t.skill(name, e.Name())
			}
		}
	}

	if len(t.b.out.Components) > before {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) geminiSettings(file string) {
	n := t.configWithParser(file, false, jsonconfig.ParseWithComments)
	if n == nil {
		return
	}

	t.servers(n.Get(mcpServersField), file, mcpServersPointer)
	hooks := n.Get("hooks")
	t.geminiHooks(hooks, file, true)
	t.enablementList(n.Get("mcp").Get("allowed"), file, "/mcp/allowed", kindMCPServer, true)
	t.enablementList(n.Get("mcp").Get("excluded"), file, "/mcp/excluded", kindMCPServer, false)
	t.enablementList(n.Get(fieldSkills).Get("disabled"), file, "/skills/disabled", "skill", false)

	if enabled := n.Get("hooksConfig").Get(fieldEnabled); enabled != nil {
		t.geminiToggle(enabled, file, "/hooksConfig/enabled", kindHook)
	} else {
		t.geminiToggle(hooks.Get(fieldEnabled), file, "/hooks/enabled", kindHook)
	}

	t.geminiToggle(n.Get(fieldSkills).Get(fieldEnabled), file, "/skills/enabled", "skill")
}

func (t *tree) geminiToggle(n *jsonconfig.Node, file, key, kind string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindBool {
		t.b.issue(codeInvalidEnablement, t.absolute(file))
		return
	}

	t.setting(kind, "*", declaredState(n.Bool), file, key)
}

func (t *tree) geminiHooks(hooks *jsonconfig.Node, file string, settings bool) {
	if hooks == nil {
		return
	}

	if hooks.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range hooks.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if settings && agentconfig.HookSetting(event.Key) {
			continue
		}

		if !hookevent.Gemini(event.Key) || event.Value.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		t.geminiHookGroups(event, file)
	}
}

func (t *tree) geminiHookGroups(event jsonconfig.Member, file string) {
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

			kind, _ := handler.Get("type").Text()

			command, _ := handler.Get("command").Text()
			if kind != "command" || strings.TrimSpace(command) == "" {
				t.b.issue(codeInvalidPluginHooks, t.absolute(file))
				continue
			}

			key := "/hooks/" + pointer(event.Key) + "/" + strconv.Itoa(i) + "/hooks/" + strconv.Itoa(j)
			t.component(kindHook, event.Key, file, file, key, "unknown")
		}
	}
}

func (t *tree) geminiExtensions(root string) {
	for _, e := range t.entries(root) {
		dir := path.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(dir))
		} else if e.IsDir() {
			t.geminiExtension(dir)
		}
	}
}

func (t *tree) geminiExtension(dir string) {
	file := path.Join(dir, agentconfig.GeminiManifest)

	n := t.config(file, false)
	if n == nil {
		return
	}

	name, _ := n.Get(fieldName).Text()

	version, _ := n.Get("version").Text()
	if !agentconfig.ValidNamedExtension(name, version) {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	extension := *t
	extension.scope, extension.plugin = "plugin", name
	extension.component("plugin", name, dir, file, "", "unknown")
	extension.b.target(t.absolute(dir))

	extension.servers(n.Get(mcpServersField), file, mcpServersPointer)
	extension.extensionContexts(dir, file, n.Get(agentconfig.ExtensionContextField), agentconfig.GeminiContext)
	extension.geminiInstructions(dir)
	extension.geminiSkills(path.Join(dir, "skills"))

	hooksFile := path.Join(dir, "hooks/hooks.json")
	if cfg := extension.config(hooksFile, false); cfg != nil {
		if hooks := cfg.Get("hooks"); hooks != nil {
			extension.geminiHooks(hooks, hooksFile, false)
		} else {
			extension.b.issue(codeInvalidPluginHooks, extension.absolute(hooksFile))
		}
	}
}

func (t *tree) geminiContext(file string) {
	t.geminiContextFile(file, false)
}

func (t *tree) geminiContextFile(file string, required bool) {
	if t.read(file, required) != nil {
		t.component(kindRule, path.Base(file), file, file, "", "unknown")
	}
}

func (t *tree) extensionContexts(dir, file string, n *jsonconfig.Node, fallback string) {
	if n == nil {
		t.geminiContext(path.Join(dir, fallback))
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

		value, ok := item.Text()

		rel, reason := artifactpath.Reference(value, false)
		if !ok || reason != "" || rel == "." {
			t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
			continue
		}

		t.geminiContextFile(path.Join(dir, rel), true)
	}
}
