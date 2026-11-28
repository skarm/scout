package discovery

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	fieldEnabledPlugins = "enabledPlugins"
	fieldProjects       = "projects"
)

const (
	codeAncestorLimit     = "ancestor_limit"
	codeProjectUnreadable = "project_unreadable"
)

const (
	maxDiscoveryAncestorDepth = 64
)

const (
	codexHomeDirectory  = ".codex"
	claudeHomeDirectory = ".claude"
	claudeGlobalConfig  = ".claude.json"
	mcpServersField     = "mcpServers"
	mcpServersPointer   = "/" + mcpServersField
)

const kindMCPServer = "mcp-server"

const codeInvalidRoot = "invalid_root"

func (b *builder) user() {
	for _, agent := range b.agents {
		override := *agent.homeOverride(&b.options)
		b.open(b.options.Home, agent.id, "user", true, func(t *tree) {
			t.readLocations(agent.user)

			if override == "" {
				t.readLocations(agent.defaultHome)
			}
		})

		if override != "" {
			b.open(override, agent.id, "user", false, func(t *tree) { t.readLocations(agent.relocated) })
		}
	}
}

func (t *tree) readLocations(locations []location) {
	for _, item := range locations {
		// A nil reader protects an alternate path handled by another location.
		if item.read != nil {
			item.read(t, item.path)
		}
	}
}

func (t *tree) codex(base string) {
	t.codexConfig(path.Join(base, "config.toml"))
	t.skills(path.Join(base, "skills"))
	t.plugins(path.Join(base, "plugins/cache"))
}

func (t *tree) claude(base string) {
	t.settings(path.Join(base, artifact.ClaudeSettings))
	t.skills(path.Join(base, "skills"))
	t.commands(path.Join(base, "commands"))

	for _, dir := range []string{"cache", "repos", "synced"} {
		t.plugins(path.Join(base, "plugins", dir))
	}
}

func (t *tree) claudeGlobal(name string) {
	// The ordinary and explicit agent homes can refer to the same root.
	if _, found := t.b.sources[t.absolute(name)]; found {
		return
	}

	n := t.config(name, false)
	if n == nil {
		return
	}

	t.servers(n.Get(mcpServersField), name, mcpServersPointer)

	for _, project := range n.GetOrEmpty(fieldProjects).Members {
		if !filepath.IsAbs(project.Key) || !t.b.selectedProject(project.Key) {
			continue
		}

		local := *t
		local.scope, local.project = "project", project.Key
		key := "/projects/" + pointer(project.Key)
		local.servers(project.Value.Get(mcpServersField), name, key+mcpServersPointer)

		for _, field := range []string{"disabledMcpServers", "enabledMcpServers"} {
			local.enablementList(project.Value.Get(field), name, key+"/"+field, kindMCPServer, field == "enabledMcpServers")
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
			b.issue(codeInvalidRoot, selected)
			continue
		}

		b.protectProjectAncestors(absolute)

		resolved, err := b.options.resolveRoot(absolute)
		if err != nil {
			b.issue(codeProjectUnreadable, absolute)
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
		if b.stopped || b.ctx.Err() != nil {
			return
		}

		b.ancestors(b.sourcePaths.canonical(root), b.options.projectBoundaries[root])
	}
}

func (b *builder) ancestors(dir, boundary string) {
	for depth := 0; depth < maxDiscoveryAncestorDepth && !b.stopped && b.ctx.Err() == nil; depth++ {
		for _, agent := range b.agents {
			b.open(dir, agent.id, "project", true, func(t *tree) {
				t.project = t.base
				t.readLocations(agent.project)
			})
		}

		if dir == boundary {
			return
		}

		dir = projectParent(dir, b.options.Home)
		if dir == "" {
			return
		}
	}

	if !b.stopped && b.ctx.Err() == nil {
		b.issue(codeAncestorLimit, dir)
	}
}

func projectParent(dir, home string) string {
	_, gitErr := os.Lstat(filepath.Join(dir, ".git"))
	if parent := filepath.Dir(dir); gitErr != nil && parent != dir && !samePath(dir, home) {
		return parent
	}

	return ""
}

func samePath(a, b string) bool {
	absolute, err := filepath.EvalSymlinks(b)
	return err == nil && a == absolute
}

func (t *tree) codexProject(base string) {
	t.codexConfig(path.Join(base, "config.toml"))
}

func (t *tree) claudeProject(base string) {
	t.settings(path.Join(base, artifact.ClaudeSettings))
	t.settings(path.Join(base, artifact.ClaudeLocalSettings))
	t.skills(path.Join(base, "skills"))
	t.commands(path.Join(base, "commands"))
}

func (b *builder) system() {
	for _, agent := range b.agents {
		if root := agent.systemRoot(); root != "" {
			b.open(root, agent.id, "system", false, func(t *tree) { t.readLocations(agent.system) })
		}
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
		t.enablement(n.Get(fieldEnabledPlugins), source, "/"+fieldEnabledPlugins, "plugin")

		for _, key := range []string{"enabledMcpjsonServers", "disabledMcpjsonServers"} {
			t.enablementList(n.Get(key), source, "/"+key, kindMCPServer, key == "enabledMcpjsonServers")
		}
	}
}

func (t *tree) enablementList(n *jsonconfig.Node, source, key, kind string, enabled bool) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindArray {
		t.b.issue(codeInvalidEnablement, t.absolute(source))
		return
	}

	for i, entry := range n.Elements {
		if !t.b.step(t.absolute(source)) {
			return
		}

		if value, ok := entry.Text(); ok {
			t.setting(kind, value, declaredState(enabled), source, key+"/"+strconv.Itoa(i))
		} else {
			t.b.issue(codeInvalidEnablement, t.absolute(source))
		}
	}
}

func (t *tree) enablement(n *jsonconfig.Node, source, key, kind string) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidEnablement, t.absolute(source))
		return
	}

	for _, entry := range n.Members {
		if entry.Value.Kind != jsonconfig.KindBool {
			t.b.issue(codeInvalidEnablement, t.absolute(source))
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
