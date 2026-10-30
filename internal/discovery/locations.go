package discovery

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (b *builder) user() {
	if b.selects("codex") {
		b.open(b.options.Home, "codex", "user", true, func(t *tree) {
			t.skills(".agents/skills")

			if b.options.CodexHome == "" {
				t.codex(".codex")
			}
		})

		if b.options.CodexHome != "" {
			b.open(b.options.CodexHome, "codex", "user", false, func(t *tree) { t.codex(".") })
		}
	}

	if b.selects("claude-code") {
		b.open(b.options.Home, "claude-code", "user", true, func(t *tree) {
			t.claudeGlobal(".claude.json")

			if b.options.ClaudeHome == "" {
				t.claude(".claude")
			}
		})

		if b.options.ClaudeHome != "" {
			b.open(b.options.ClaudeHome, "claude-code", "user", false, func(t *tree) {
				t.claudeGlobal(".claude.json")
				t.claude(".")
			})
		}
	}
}

func (t *tree) codex(base string) {
	t.codexConfig(path.Join(base, "config.toml"))
	t.skills(path.Join(base, "skills"))
	t.plugins(path.Join(base, "plugins/cache"))
}

func (t *tree) claude(base string) {
	t.settings(path.Join(base, "settings.json"))
	t.skills(path.Join(base, "skills"))
	t.commands(path.Join(base, "commands"))

	for _, dir := range []string{"cache", "repos", "synced"} {
		t.plugins(path.Join(base, "plugins", dir))
	}
}

func (t *tree) claudeGlobal(name string) {
	n := t.config(name, false)
	if n == nil {
		return
	}

	t.servers(n.Get("mcpServers"), name, "/mcpServers")

	for _, project := range n.GetOrEmpty("projects").Members {
		if !filepath.IsAbs(project.Key) || !t.b.selectedProject(project.Key) {
			continue
		}

		local := *t
		local.scope, local.project = "project", project.Key
		key := "/projects/" + pointer(project.Key)
		local.servers(project.Value.Get("mcpServers"), name, key+"/mcpServers")

		for _, field := range []string{"disabledMcpServers", "enabledMcpServers"} {
			local.mcpEnablement(project.Value.Get(field), name, key+"/"+field, field == "enabledMcpServers")
		}
	}
}

func (b *builder) selectedProject(name string) bool {
	for _, selected := range b.projectNames {
		if within(name, selected) {
			return true
		}
	}

	return false
}

// Resolve only caller-selected paths, before reading registrations. Configuration
// keys remain data: they never cause filesystem access outside these roots.
func (b *builder) prepareProjects() {
	for _, selected := range b.options.Projects {
		absolute, err := filepath.Abs(selected)
		if err != nil {
			b.issue("invalid_root", selected)
			continue
		}

		b.protectProjectAncestors(absolute)

		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			b.issue("project_unreadable", absolute)
			continue
		}

		// Publication guards cover every selected alias even if discovery's
		// work budget or deadline was exhausted before reaching this project.
		b.protectProjectAncestors(resolved)

		if !b.step(selected) {
			continue
		}

		if !slices.Contains(b.projectRoots, resolved) {
			b.projectRoots = append(b.projectRoots, resolved)
		}

		for _, name := range []string{absolute, resolved} {
			if !slices.Contains(b.projectNames, name) {
				b.projectNames = append(b.projectNames, name)
			}
		}
	}
}

func (b *builder) projects() {
	for _, root := range b.projectRoots {
		b.ancestors(root)
	}
}

func (b *builder) ancestors(dir string) {
	for depth := 0; depth < 64 && !b.stopped && b.ctx.Err() == nil; depth++ {
		for _, agent := range []string{"codex", "claude-code"} {
			if b.selects(agent) {
				b.open(dir, agent, "project", true, func(t *tree) { t.projectFiles() })
			}
		}

		_, gitErr := os.Lstat(filepath.Join(dir, ".git"))
		if gitErr == nil || filepath.Dir(dir) == dir || samePath(dir, b.options.Home) {
			return
		}

		dir = filepath.Dir(dir)
	}

	if !b.stopped && b.ctx.Err() == nil {
		b.issue("ancestor_limit", dir)
	}
}

func samePath(a, b string) bool {
	absolute, err := filepath.EvalSymlinks(b)
	return err == nil && a == absolute
}

func (t *tree) projectFiles() {
	t.project = t.base
	if t.agent == "codex" {
		t.codexConfig(".codex/config.toml")
		t.skills(".agents/skills")
	} else {
		t.mcpFile(".mcp.json")
		t.settings(".claude/settings.json")
		t.settings(".claude/settings.local.json")
		t.skills(".claude/skills")
		t.commands(".claude/commands")
	}
}

func (b *builder) system() {
	if b.selects("codex") {
		b.open(systemRoot("codex"), "codex", "system", false, func(t *tree) {
			t.codexConfig("config.toml")
			t.skills("skills")
		})
	}

	if b.selects("claude-code") {
		b.open(systemRoot("claude-code"), "claude-code", "system", false, func(t *tree) {
			t.mcpFile("managed-mcp.json")
			t.settings("managed-settings.json")
		})
	}
}

func systemRoot(agent string) string {
	if agent == "codex" {
		if runtime.GOOS == "windows" {
			return `C:\ProgramData\OpenAI\Codex`
		}

		return "/etc/codex"
	}

	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

func (t *tree) commands(root string) {
	before := len(t.b.out.Components)
	t.walk(root, 0, func(dir string) bool {
		for _, entry := range t.entries(dir) {
			if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".md") {
				continue
			}

			file := path.Join(dir, entry.Name())
			if t.read(file, true) != nil {
				t.component("command", strings.TrimSuffix(entry.Name(), ".md"), file, file, "", "unknown")
			}
		}

		return false
	})

	if len(t.b.out.Components) > before {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) settings(source string) {
	if n := t.config(source, false); n != nil {
		t.enablement(n.Get("enabledPlugins"), source, "/enabledPlugins", "plugin")

		for _, key := range []string{"enabledMcpjsonServers", "disabledMcpjsonServers"} {
			t.mcpEnablement(n.Get(key), source, "/"+key, key == "enabledMcpjsonServers")
		}
	}
}

func (t *tree) mcpEnablement(n *jsonconfig.Node, source, key string, enabled bool) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindArray {
		t.b.issue("invalid_enablement", t.absolute(source))
		return
	}

	for i, entry := range n.Elements {
		if !t.b.step(t.absolute(source)) {
			return
		}

		if value, ok := entry.Text(); ok {
			t.setting("mcp-server", value, declaredState(enabled), source, key+"/"+strconv.Itoa(i))
		} else {
			t.b.issue("invalid_enablement", t.absolute(source))
		}
	}
}

func (t *tree) enablement(n *jsonconfig.Node, source, key, kind string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue("invalid_enablement", t.absolute(source))
		return
	}

	for _, entry := range n.Members {
		if entry.Value.Kind != jsonconfig.KindBool {
			t.b.issue("invalid_enablement", t.absolute(source))
			continue
		}

		t.setting(kind, entry.Key, declaredState(entry.Value.Bool), source, key+"/"+pointer(entry.Key))
	}
}

func (t *tree) setting(kind, selector, state, source, key string) {
	t.b.out.Enablement = append(t.b.out.Enablement, Enablement{
		Agent: t.agent, Kind: kind, Selector: selector,
		State: state, Source: t.absolute(source), Key: key, Scope: t.scope, Project: t.project,
	})
}
