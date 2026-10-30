package discovery

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) config(name string, required bool) *jsonconfig.Node {
	data := t.read(name, required)
	if data == nil {
		return nil
	}

	if strings.HasSuffix(name, ".toml") {
		var value map[string]any
		if toml.Unmarshal(data, &value) != nil {
			t.b.issue("invalid_config", t.absolute(name))
			return nil
		}

		var err error

		data, err = json.Marshal(value)
		if err != nil {
			t.b.issue("invalid_config", t.absolute(name))
			return nil
		}
	}

	n, err := jsonconfig.Parse(t.b.ctx, string(data))
	if err != nil || n.Kind != jsonconfig.KindObject {
		t.b.issue("invalid_config", t.absolute(name))
		return nil
	}

	return n
}

func (t *tree) servers(n *jsonconfig.Node, source, key string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue("invalid_mcp_config", t.absolute(source))
		return
	}

	for _, entry := range n.Members {
		if !t.b.step(t.absolute(source)) {
			return
		}

		if entry.Value.Kind != jsonconfig.KindObject {
			t.b.issue("invalid_mcp_config", t.absolute(source))
			continue
		}

		state := "unknown"

		if enabled := entry.Value.Get("enabled"); enabled != nil {
			if enabled.Kind == jsonconfig.KindBool {
				state = declaredState(enabled.Bool)
			} else {
				t.b.issue("invalid_enablement", t.absolute(source))
			}
		}

		t.component("mcp-server", entry.Key, source, source, key+"/"+pointer(entry.Key), state)
	}
}

func (t *tree) mcpFile(name string) {
	if n := t.config(name, false); n != nil {
		t.servers(n.Get("mcpServers"), name, "/mcpServers")
	}
}

func (t *tree) codexConfig(name string) {
	n := t.config(name, false)
	if n == nil {
		return
	}

	t.servers(n.Get("mcp_servers"), name, "/mcp_servers")

	for _, entry := range n.GetOrEmpty("plugins").Members {
		if enabled := entry.Value.Get("enabled"); enabled != nil && enabled.Kind == jsonconfig.KindBool {
			t.setting("plugin", entry.Key, declaredState(enabled.Bool), name, "/plugins/"+pointer(entry.Key)+"/enabled")
		}
	}

	for i, entry := range n.Get("skills").GetOrEmpty("config").Elements {
		enabled := entry.Get("enabled")

		value, ok := entry.Get("path").Text()
		if ok && enabled != nil && enabled.Kind == jsonconfig.KindBool {
			t.setting("skill", value, declaredState(enabled.Bool), name, "/skills/config/"+strconv.Itoa(i)+"/enabled")
		} else {
			t.b.issue("invalid_enablement", t.absolute(name))
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
	for _, relative := range []string{"plugin.json", ".codex-plugin/plugin.json", ".claude-plugin/plugin.json"} {
		if t.agent == "claude-code" && relative != ".claude-plugin/plugin.json" {
			continue
		}

		file := path.Join(dir, relative)

		n := t.config(file, false)
		if n == nil {
			continue
		}

		portable := relative == "plugin.json"
		if portable && !strings.HasPrefix(n.GetOrEmpty("$schema").String, "https://agent-plugins.org/schemas/") {
			continue
		}

		if portable && n.GetOrEmpty("$schema").String != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json" {
			t.b.issue("unsupported_plugin_manifest", t.absolute(file))
			return true
		}

		name, ok := n.Get("name").Text()
		if !ok || name == "" {
			t.b.issue("invalid_plugin_manifest", t.absolute(file))
			return true
		}

		plugin := *t
		plugin.scope, plugin.plugin = "plugin", name
		plugin.component("plugin", name, dir, file, "", "unknown")
		plugin.pluginSkills(dir, n.Get("skills"))

		if portable {
			plugin.mcpFile(path.Join(dir, "mcp.json"))
		} else {
			plugin.mcpFile(path.Join(dir, ".mcp.json"))
			plugin.pluginPaths(n.Get("skills"), dir, file, "/skills", true)
			plugin.pluginPaths(n.Get("mcpServers"), dir, file, "/mcpServers", false)
		}

		return true
	}

	return false
}

func (t *tree) pluginSkills(dir string, declared *jsonconfig.Node) {
	root := path.Join(dir, "skills")
	if t.agent == "claude-code" && declared == nil && !t.directory(root, false) {
		t.skill(dir, t.plugin)
		return
	}

	t.skills(root)
}

func (t *tree) manifestlessPluginAt(dir, root string) bool {
	if t.agent != "claude-code" || dir == root {
		return false
	}

	relative := strings.TrimPrefix(dir, root+"/")
	if path.Base(root) == "cache" && strings.Count(relative, "/") != 2 {
		return false
	}

	// A malformed manifest already created a gap; do not reinterpret it as an
	// absent optional manifest or infer packages at arbitrary cache depths.
	if _, present := t.b.sources[t.absolute(path.Join(dir, ".claude-plugin/plugin.json"))]; present {
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
	plugin.mcpFile(path.Join(dir, ".mcp.json"))

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
			t.b.issue("unsupported_plugin_reference", t.absolute(source))
		} else {
			t.servers(n, source, key)
		}
	case jsonconfig.KindString:
		t.pluginPath(n.String, dir, source, skills)
	default:
		t.b.issue("unsupported_plugin_reference", t.absolute(source))
	}
}

func (t *tree) pluginPath(value, dir, source string, skills bool) {
	if value != "." && !strings.HasPrefix(value, "./") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) ||
		slicesContainParent(value) {
		t.b.issue("external_plugin_reference", t.absolute(source))
		return
	}

	name := path.Join(dir, value)
	if skills {
		if t.requireDirectory(name) {
			t.skills(name)
		}
	} else if path.Ext(name) == ".json" {
		if n := t.config(name, true); n != nil {
			if wrapped := n.Get("mcpServers"); wrapped != nil {
				t.servers(wrapped, name, "/mcpServers")
			} else {
				t.servers(n, name, "")
			}
		}
	} else {
		t.b.issue("unsupported_plugin_reference", t.absolute(source))
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
