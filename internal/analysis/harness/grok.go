package harness

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func grokWorkspaceRoot(name, requested string) (string, bool) {
	if root, ok := artifact.GrokTOMLRoot(name, requested); ok {
		return root, true
	}

	if root, ok := workspaceDirectory(name, artifact.GrokDirectory, artifact.GrokLSP, "agents", "commands", "hooks", "skills", "workflows"); ok {
		return root, true
	}

	return ".", requested == report.HostGrokCLI && path.Dir(name) == "." &&
		(name == artifact.GrokLSP || agentconfig.InstructionFile(requested, componentWorkflow, name))
}

func grokLocalPackageRoot(name string) (string, bool) {
	prefix, rest, ok := strings.Cut("/"+name, "/"+artifact.GrokDirectory+"/plugins/")

	plugin, file, child := strings.Cut(rest, "/")
	if !ok || !child || plugin == "marketplaces" || !grokPackageFile(file) {
		return "", false
	}

	return path.Join(strings.TrimPrefix(prefix, "/"), artifact.GrokDirectory, "plugins", plugin), true
}

func grokPackageFile(name string) bool {
	switch name {
	case artifact.MCPConfig, ".lsp.json", defaultHooksPath:
		return true
	}

	dir, _, ok := strings.Cut(name, "/")
	switch dir {
	case "agents", "commands":
		return ok && agentconfig.InstructionFile(report.HostGrokCLI, dir, name)
	case "skills":
		return path.Base(name) == artifact.SkillManifest
	default:
		return false
	}
}

func grokStandalonePackage(ns *namespace) bool {
	for _, dir := range []string{artifact.GrokConfig, artifact.GrokManagedConfig, artifact.GrokRequirements, artifact.GrokLSP} {
		if ns.entries[dir] != nil {
			return false
		}
	}

	for _, name := range []string{artifact.MCPConfig, ".lsp.json", defaultHooksPath} {
		if ns.entries[name] != nil {
			return true
		}
	}

	// A captured directory with instructions alone can also be a Grok home.
	// The same conventional component selection covers both interpretations.
	for _, dir := range []string{"agents", "commands", "skills"} {
		if len(ns.descendants(dir)) != 0 {
			return true
		}
	}

	return false
}

func grokPluginProfile(ns *namespace, root, native, requested string) bool {
	switch native {
	case report.HostGrokCLI:
		return true
	case "unknown", report.HostClaudeCode:
		if requested == report.HostGrokCLI || ns.entries[path.Join(root, artifact.GrokPluginManifest)] != nil {
			return true
		}

		return strings.Contains("/"+root+"/", "/"+artifact.GrokDirectory+"/plugins/")
	default:
		return false
	}
}

func grokManifest(ns *namespace, root string) string {
	if file := path.Join(root, agentplugins.ManifestFile); agentplugins.ManifestVersion(capturedJSON(ns.entries[file])) != "" {
		return file
	}

	for _, legacy := range agentconfig.GrokLegacyManifests() {
		if file := path.Join(root, legacy); ns.entries[file] != nil && !grokMarketplace(ns, file) {
			return file
		}
	}

	return ""
}

func grokMarketplace(ns *namespace, name string) bool {
	if strings.HasSuffix("/"+name, "/"+artifact.GrokMarketplaceManifest) {
		return true
	}

	return strings.HasSuffix("/"+name, "/"+artifact.GrokPluginManifest) && agentconfig.GrokMarketplaceIndex(capturedJSON(ns.entries[name]))
}

func (p *plugin) discoverGrokPackage() {
	n := p.object(p.manifest)
	if n != nil {
		p.validateManifest(n)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.directory(fieldSkills, "skills", n, report.ComponentSkill, false)
	p.directory(fieldAgents, "agents", n, componentAgent, true)
	p.directory(fieldCommands, "commands", n, componentCommand, true)
	p.configs(fieldMCPServers, artifact.MCPConfig, report.ComponentMCPConfig, n)
	p.configs(fieldLSPServers, ".lsp.json", componentLSPConfig, n)
	p.configs(fieldHooks, defaultHooksPath, report.ComponentHookConfig, n)
}

func (p *plugin) grokWorkspace() {
	base := artifact.GrokDirectory
	if path.Dir(p.manifest.name) == p.root {
		base = "."
	}

	for _, name := range []string{artifact.GrokConfig, artifact.GrokManagedConfig, artifact.GrokRequirements} {
		p.grokTOML(p.entry(path.Join(base, name)))
	}

	p.defaultNativeConfig(path.Join(base, artifact.GrokLSP), componentLSPConfig, false)

	if base == "." && agentconfig.InstructionFile(p.host, componentWorkflow, p.manifest.name) {
		p.component(componentWorkflow, p.manifest, p.activation, selectionHostDefault, whole(p.manifest), "file")
	}

	for _, item := range []struct{ dir, kind string }{
		{"agents", componentAgent}, {"commands", componentCommand}, {"skills", report.ComponentSkill}, {"workflows", componentWorkflow},
	} {
		p.selectFiles(path.Join(base, item.dir), item.kind, p.activation, selectionHostDefault, nil, false)
	}

	p.grokWorkspaceHooks(base)
}

func (p *plugin) grokWorkspaceHooks(base string) {
	dir := path.Join(base, "hooks")
	absolute := path.Join(p.root, dir)

	for _, name := range p.ns.descendants(absolute) {
		if !p.b.step() {
			return
		}

		if path.Dir(name) == absolute && path.Ext(name) == ".json" {
			p.defaultNativeConfig(path.Join(dir, path.Base(name)), report.ComponentHookConfig, false)
		}
	}

	if len(p.ns.names) == 1 && base == "." && hasNativeHooks(p.manifest) {
		p.defaultNativeConfig(path.Base(p.manifest.name), report.ComponentHookConfig, false)
	}
}

func (p *plugin) grokTOML(e *entry) {
	n := p.object(e)
	if n.Get(fieldMCPServersSnake) != nil {
		s := whole(e)
		id := p.component(report.ComponentMCPConfig, e, p.activation, basisConfiguration, s, "grok-mcp")
		p.b.edge(p.rootNode, id, relationDeclares, basisConfiguration, p.activation, s)
		p.servers(e, n, report.ComponentMCPConfig, id, p.activation)
	}

	if n.Get(fieldHooks) != nil {
		// A captured config.toml may come from a user home or a project,
		// whose inline hooks have different loader semantics.
		p.configFile(e, report.ComponentHookConfig, activationUnknown, basisConfiguration, whole(e))
	}
}

func (p *plugin) grokHookCommand(e *entry, id, command, activation string, s *report.SourceRef) {
	dir := ""
	if path.Ext(e.name) == ".json" {
		dir = path.Dir(strings.TrimPrefix(e.name, p.root+"/"))
	}

	p.commandFrom(id, command, nil, false, s, activation, !p.nativeWorkspace, dir)
}

func grokRelativeExecutable(dir, name string) (string, bool) {
	if strings.HasPrefix(name, "/") || !strings.Contains(name, "/") || strings.ContainsAny(name, "\\:\x00\r\n\t$~*?[]{}") {
		return "", false
	}

	rel, reason := artifactpath.Reference(path.Join(dir, name), false)

	return rel, reason == "" && rel != "."
}
