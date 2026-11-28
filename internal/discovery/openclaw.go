package discovery

import (
	"os"
	"path"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const codeOpenClawIncludeUnresolved = "openclaw_include_unresolved"

func (t *tree) openClawState(base string) {
	t.openClawConfig(path.Join(base, artifact.OpenClawConfig))
	t.skills(path.Join(base, "skills"))
	t.openClawHooks(path.Join(base, "hooks"))
	t.openClawPackages(path.Join(base, "extensions"))

	workspace := path.Join(base, "workspace")
	local := *t
	local.scope, local.project = "project", t.absolute(workspace)
	local.skills(path.Join(workspace, "skills"))
	local.skills(path.Join(workspace, ".agents/skills"))
	local.openClawHooks(path.Join(workspace, "hooks"))
	local.openClawPackages(path.Join(workspace, artifact.OpenClawDirectory, "extensions"))
}

func (t *tree) openClawConfig(file string) {
	n := t.config(file, false)
	if n == nil {
		return
	}

	t.servers(n.Get("mcp").Get("servers"), file, "/mcp/servers")

	for _, kind := range []struct{ field, kind string }{{"skills", "skill"}, {"plugins", "plugin"}} {
		t.openClawEntries(n.Get(kind.field), file, "/"+kind.field, kind.kind)
	}

	t.openClawEntries(n.Get("hooks").Get("internal"), file, "/hooks/internal", kindHook)
	t.enablementList(n.Get("plugins").Get("allow"), file, "/plugins/allow", "plugin", true)
	t.enablementList(n.Get("plugins").Get("deny"), file, "/plugins/deny", "plugin", false)

	for range agentconfig.OpenClawIncludes(t.b.ctx, n) {
		t.b.issue(codeOpenClawIncludeUnresolved, t.absolute(file))
		break
	}
}

func (t *tree) openClawEntries(n *jsonconfig.Node, file, key, kind string) {
	if value := n.Get(fieldEnabled); value != nil {
		t.openClawEnabled(value, file, key+"/enabled", kind, "*")
	}

	entries := n.Get("entries")
	if entries == nil {
		return
	}

	if entries.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidEnablement, t.absolute(file))
		return
	}

	for _, entry := range entries.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if value := entry.Value.Get(fieldEnabled); value != nil {
			t.openClawEnabled(value, file, key+"/entries/"+pointer(entry.Key)+"/enabled", kind, entry.Key)
		}
	}
}

func (t *tree) openClawEnabled(n *jsonconfig.Node, file, key, kind, selector string) {
	if n.Kind != jsonconfig.KindBool {
		t.b.issue(codeInvalidEnablement, t.absolute(file))
		return
	}

	t.setting(kind, selector, declaredState(n.Bool), file, key)
}

func (t *tree) openClawPackages(root string) {
	for _, entry := range t.entries(root) {
		dir := path.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(dir))
		} else if entry.IsDir() {
			t.openClawPackage(dir)
		}
	}
}

func (t *tree) openClawPackage(dir string) {
	file := path.Join(dir, artifact.OpenClawManifest)

	manifest := t.config(file, false)
	if manifest != nil {
		t.openClawNativePackage(dir, file, manifest)
		return
	}

	if _, present := t.b.sources[t.absolute(file)]; present {
		return
	}

	file = path.Join(dir, "package.json")
	packageJSON := t.config(file, false)

	metadata := packageJSON.Get(agentconfig.OpenClawPackageKey)
	if agentconfig.OpenClawPackageDeclared(metadata) {
		id := agentconfig.OpenClawPackageID(packageJSON, path.Base(dir))
		p := t.openClawPackageInventory(dir, file, id)
		p.openClawPathList(metadata.Get("hooks"), dir, file, p.openClawHookRoot)
	}
}

func (t *tree) openClawNativePackage(dir, file string, manifest *jsonconfig.Node) {
	id, ok := agentconfig.OpenClawPluginID(manifest)
	if !ok {
		t.b.issue(codeInvalidPluginManifest, t.absolute(file))
		return
	}

	p := t.openClawPackageInventory(dir, file, id)
	p.openClawPathList(manifest.Get("skills"), dir, file, p.openClawSkillRoot)

	meta := path.Join(dir, "package.json")
	metadata := p.config(meta, false).Get(agentconfig.OpenClawPackageKey)
	p.openClawPathList(metadata.Get("hooks"), dir, meta, p.openClawHookRoot)
}

func (t *tree) openClawPackageInventory(dir, file, id string) tree {
	p := *t
	p.scope, p.plugin = "plugin", id
	p.component("plugin", id, dir, file, "", "unknown")
	p.b.target(p.absolute(dir))

	return p
}

func (t *tree) openClawSkillRoot(dir string) {
	if t.requireDirectory(dir) {
		t.skills(dir)
	}
}

func (t *tree) openClawPathList(list *jsonconfig.Node, root, file string, collect func(string)) {
	if list == nil {
		return
	}

	if list.Kind != jsonconfig.KindArray {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(file))
		return
	}

	for _, n := range list.Elements {
		if !t.b.step(t.absolute(file)) {
			return
		}

		raw, _ := n.Text()

		rel, reason := artifactpath.Reference(raw, false)
		if reason != "" {
			t.b.issue(codeExternalPluginReference, t.absolute(file))
			continue
		}

		collect(path.Join(root, rel))
	}
}

func (t *tree) openClawHooks(root string) {
	for _, entry := range t.entries(root) {
		dir := path.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			t.b.issue(codeSymlinkRefused, t.absolute(dir))
		} else if entry.IsDir() && !t.openClawHook(dir) {
			file := path.Join(dir, "package.json")
			metadata := t.config(file, false).Get(agentconfig.OpenClawPackageKey)
			t.openClawPathList(metadata.Get("hooks"), dir, file, t.openClawHookRoot)
		}
	}
}

func (t *tree) openClawHookRoot(dir string) {
	if !t.openClawHook(dir) {
		t.b.issue(codeUnsupportedPluginReference, t.absolute(path.Join(dir, artifact.OpenClawHookManifest)))
	}
}

func (t *tree) openClawHook(dir string) bool {
	file := path.Join(dir, artifact.OpenClawHookManifest)
	if t.read(file, false) == nil {
		return false
	}

	t.component(kindHook, path.Base(dir), dir, file, "", "unknown")
	t.b.target(t.absolute(dir))

	return true
}
