package harness

import (
	"fmt"
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func kimiManifest(ns *namespace, root string) string {
	for _, relative := range agentconfig.KimiManifests() {
		if name := path.Join(root, relative); ns.entries[name] != nil {
			return name
		}
	}

	return ""
}

func kimiWorkspaceCandidate(ns *namespace, name, requested string) (candidate, bool) {
	root, ok := kimiWorkspaceRoot(name, requested)
	if !ok || kimiManifest(ns, root) != "" {
		return candidate{}, false
	}

	return candidate{ns: ns, root: root, host: report.HostKimiCode, manifest: name, nativeWorkspace: true}, true
}

func kimiWorkspaceRoot(name, host string) (string, bool) {
	if dir, ok := artifact.KimiTOMLRoot(name, host); ok {
		if path.Base(dir) == artifact.KimiDirectory || path.Base(dir) == artifact.KimiLegacyDirectory {
			return path.Dir(dir), true
		}

		return dir, true
	}

	if root, ok := workspaceDirectory(name, artifact.KimiDirectory, "AGENTS.md", "SYSTEM.md", artifact.KimiMCP, "agents", "skills"); ok {
		return root, true
	}

	if root, ok := strings.CutSuffix("/"+name, "/"+path.Join(artifact.KimiDirectory, artifact.KimiInstallIndex)); ok {
		return path.Clean(strings.TrimPrefix(root, "/")), true
	}

	if root, ok := workspaceDirectory(name, artifact.KimiLegacyDirectory, artifact.KimiMCP, "skills"); ok {
		return root, true
	}

	return ".", host == report.HostKimiCode && kimiStandalone(name)
}

func kimiStandalone(name string) bool {
	switch name {
	case "AGENTS.md", "agents.md", "SYSTEM.md", artifact.KimiMCP, artifact.KimiInstallIndex, path.Base(artifact.KimiInstallIndex):
		return true
	}

	for _, root := range []string{"agents", "skills", ".agents/agents", ".agents/skills"} {
		if strings.HasPrefix(name, root+"/") {
			return true
		}
	}

	return false
}

func (p *plugin) kimiWorkspace() {
	p.kimiContext("AGENTS.md", "agents.md")
	p.kimiWorkspaceDirectory(artifact.KimiDirectory, true)
	p.kimiWorkspaceDirectory(artifact.KimiLegacyDirectory, false)
	p.kimiSkills(".agents/skills", false, nil)
	p.selectFiles(".agents/agents", componentAgent, p.activation, selectionHostDefault, nil, false)

	if p.b.r.RequestedHost == report.HostKimiCode {
		// An explicitly selected capture may be a relocated Kimi home or a file.
		if len(p.ns.descendants(path.Join(p.root, artifact.KimiDirectory))) == 0 {
			p.kimiWorkspaceDirectory(".", true)
			p.kimiContext(".agents/AGENTS.md", ".agents/agents.md")
		}

		if p.manifest.name == path.Base(artifact.KimiInstallIndex) {
			p.kimiInstalled(p.manifest)
		}
	}
}

func (p *plugin) kimiWorkspaceDirectory(base string, current bool) {
	p.kimiMCP(p.entry(path.Join(base, artifact.KimiMCP)))

	if config := p.entry(path.Join(base, artifact.KimiConfig)); config != nil && p.object(config).Get(fieldHooks) != nil {
		// The captured file alone cannot establish that it came from the user home.
		p.configFile(config, report.ComponentHookConfig, activationUnknown, basisConfiguration, whole(config))
	}

	p.kimiSkills(path.Join(base, "skills"), false, nil)

	if current {
		if base != "." {
			p.kimiContext(path.Join(base, "AGENTS.md"), "")
		}

		p.kimiContext(path.Join(base, "SYSTEM.md"), "")
		p.selectFiles(path.Join(base, "agents"), componentAgent, p.activation, selectionHostDefault, nil, false)
		p.kimiInstalled(p.entry(path.Join(base, artifact.KimiInstallIndex)))
	}
}

func (p *plugin) kimiContext(primary, fallback string) {
	e := p.entry(primary)
	if (e == nil || e.Doc != nil && strings.TrimSpace(e.Doc.Artifact().Content()) == "") && fallback != "" {
		e = p.entry(fallback)
	}

	if e != nil {
		p.component(componentRule, e, p.activation, basisConfiguration, whole(e), "kimi-instructions")
	}
}

func (p *plugin) discoverKimiPlugin() {
	n := p.object(p.manifest)

	name, _ := n.Get(fieldName).Text()
	if !agentconfig.KimiPluginID(strings.TrimSpace(name)) {
		p.issue(issuePluginMetadataTypeInvalid, p.manifestPath(), formatInvalid)
		return
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.kimiMCP(p.manifest)

	if n.Get(fieldHooks) != nil {
		p.configFile(p.manifest, report.ComponentHookConfig, p.activation, basisManifest, whole(p.manifest))
	}

	p.kimiPluginPaths(n.Get(fieldCommands), componentCommand)

	if agents := n.Get(fieldAgents); agents != nil {
		p.kimiPluginPaths(agents, componentAgent)
	} else {
		p.selectFiles("agents", componentAgent, p.activation, selectionHostDefault, nil, false)
	}

	if skills := n.Get(fieldSkills); skills != nil {
		p.kimiPluginPaths(skills, report.ComponentSkill)
	} else if e := p.entry(artifact.SkillManifest); e != nil {
		p.selectedFile(e.name, p.root, report.ComponentSkill, p.activation, selectionHostDefault, nil)
	}

	p.kimiPrompt(n)
}

func (p *plugin) kimiPrompt(n *jsonconfig.Node) {
	for _, instruction := range agentconfig.KimiPluginInstructions(n) {
		p.component(componentRule, p.manifest, p.activation, basisManifest, ref(p.manifest, instruction.Node.Span), instruction.Name)
	}

	if declared := n.Get("systemPromptPath"); declared != nil {
		name, _ := declared.Text()
		s := ref(p.manifest, declared.Span)

		rel, reason := artifactpath.Reference(name, true)
		if reason != "" || rel == "." {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
		} else if e := p.entry(rel); e != nil {
			id := p.component(componentRule, e, p.activation, basisManifest, whole(e), "system-prompt-file")
			p.b.edge(p.rootNode, id, relationDeclares, basisManifest, p.activation, s)
		} else {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
		}
	}
}

func (p *plugin) kimiPluginPaths(n *jsonconfig.Node, kind string) {
	if n == nil {
		return
	}

	for _, item := range pathValues(n) {
		if !p.b.step() {
			return
		}

		raw, _ := item.Text()
		rel, reason := artifactpath.Reference(raw, true)

		s := ref(p.manifest, item.Span)
		if rel == "." && raw != "./" || reason != "" {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
			continue
		}

		switch kind {
		case report.ComponentSkill:
			p.kimiSkills(rel, true, s)
		case componentAgent:
			if p.HasDirectory(rel) {
				p.selectFiles(rel, kind, p.activation, basisManifest, s, false)
			} else {
				p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
			}
		default:
			p.selectFiles("./"+rel, kind, p.activation, basisManifest, s, true)
		}
	}
}

func (p *plugin) kimiSkills(dir string, plugin bool, s *report.SourceRef) {
	root := path.Join(p.root, dir)

	basis := selectionHostDefault
	if s != nil {
		basis = basisManifest
	}

	found := false

	for _, name := range p.ns.selectNames(root) {
		if !p.b.step() {
			return
		}

		if p.kimiSkillFile(name, root, plugin) {
			found = true

			p.selectedFile(name, root, report.ComponentSkill, p.activation, basis, s)
		}
	}

	if s != nil && !found {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
	}
}

func (p *plugin) kimiSkillFile(name, root string, plugin bool) bool {
	dir, file := path.Dir(name), path.Base(name)
	if file != artifact.SkillManifest {
		return dir == root && path.Ext(file) == ".md" &&
			p.ns.entries[path.Join(root, strings.TrimSuffix(file, ".md"), artifact.SkillManifest)] == nil
	}

	if dir == root {
		return plugin
	}

	for parent := path.Dir(dir); parent != "." && parent != root; parent = path.Dir(parent) {
		if strings.HasPrefix(path.Base(parent), ".") || p.ns.entries[path.Join(parent, artifact.SkillManifest)] != nil {
			return false
		}
	}

	return !strings.HasPrefix(path.Base(dir), ".")
}

func (p *plugin) kimiMCP(e *entry) {
	if n := p.object(e); n.Get(fieldMCPServers) != nil {
		p.configFile(e, report.ComponentMCPConfig, p.activation, basisConfiguration, whole(e))
	}
}

func (p *plugin) kimiHooks(e *entry, n *jsonconfig.Node, parent, activation string) {
	hooks := n.Get(fieldHooks)
	if hooks == nil || hooks.Kind != jsonconfig.KindArray {
		p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, item := range hooks.Elements {
		if !p.b.step() {
			return
		}

		command := agentconfig.KimiHookCommand(item)
		if command == nil {
			p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		s := ref(e, item.Span)
		id := p.component(report.ComponentHook, e, activation, basisConfiguration, s, fmt.Sprintf("kimi-hook:%d", i))
		p.b.edge(parent, id, relationRegisters, basisConfiguration, activation, s)

		dir := "."
		if p.nativeWorkspace {
			dir = ""
		}

		p.commandFrom(id, command.String, nil, false, s, activation, !p.nativeWorkspace, dir)
	}
}

func (p *plugin) kimiInstalled(e *entry) {
	if e == nil {
		return
	}

	plugins := p.object(e).Get("plugins")
	if plugins == nil || plugins.Kind != jsonconfig.KindArray {
		p.issue(issuePluginConfigShapeInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, record := range plugins.Elements {
		if !p.b.step() {
			return
		}

		_, _, enabled, valid := agentconfig.KimiInstalledRecord(record)
		if !valid {
			p.issue(issuePluginConfigShapeInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		activation := p.activation
		if !enabled {
			activation = activationInactiveForProfile
		}

		p.component(componentExtension, e, activation, basisSettings, ref(e, record.Span), fmt.Sprintf("kimi-installed:%d", i))
	}
}

func (p *plugin) kimiServer(e *entry, n *jsonconfig.Node, id, activation string, s *report.SourceRef) {
	switch agentconfig.KimiMCPTransport(n) {
	case "stdio":
		p.serverCommand(e, n, id, s, activation)
	case "http", "sse":
		if n.Get(fieldURL) == nil {
			p.issue(issuePluginServerURLInvalid, e.Meta.Path, formatInvalid)
		} else {
			p.serverEndpoints(e, id, []*jsonconfig.Node{n.Get(fieldURL)})
		}
	default:
		p.issue(issuePluginServerTransportUnverified, e.Meta.Path, report.OutcomePartial)
	}
}

func (p *plugin) kimiServerCommand(e *entry, n *jsonconfig.Node, id, command string, args []string, s *report.SourceRef, activation string) {
	if agentconfig.KimiRemoteMCP(n) {
		p.reference(id, referenceKindRuntime, report.ReferenceUnresolved, report.ReferenceReasonRuntimeNotMaterialized, "", s)
		return
	}

	dir := ""
	if !p.nativeWorkspace {
		dir = p.kimiPluginServerDir(e, n, command)
		if dir == "" && (n.Get("cwd") != nil || strings.ContainsAny(command, "/\\")) {
			p.reference(id, referenceKindCommand, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
			return
		}
	}

	p.commandFrom(id, command, args, true, s, activation, false, dir)
}

func (p *plugin) kimiPluginServerDir(e *entry, n *jsonconfig.Node, command string) string {
	cwd := n.Get("cwd")
	dir := ""

	if cwd != nil {
		raw, _ := cwd.Text()

		rel, reason := artifactpath.Reference(raw, true)
		if !strings.HasPrefix(raw, "./") || reason != "" {
			p.issue(issuePluginServerCommandInvalid, e.Meta.Path, formatInvalid)
			return ""
		}

		dir = rel
	}

	if strings.HasPrefix(command, "./") {
		return "."
	}

	if strings.ContainsAny(command, "/\\") {
		p.issue(issuePluginServerCommandInvalid, e.Meta.Path, formatInvalid)
		return ""
	}

	return dir
}
