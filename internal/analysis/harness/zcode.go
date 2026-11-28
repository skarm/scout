package harness

import (
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func zcodePluginProfile(ns *namespace, root, native, requested string) bool {
	if native == report.HostZCode {
		return true
	}

	return native == report.HostClaudeCode && (requested == report.HostZCode ||
		ns.entries[path.Join(root, artifact.ZCodePluginManifest)] != nil ||
		strings.Contains("/"+root+"/", "/"+path.Join(artifact.ZCodeDirectory, artifact.ZCodePluginCache)+"/"))
}

func zcodeManifest(ns *namespace, root string) string {
	for _, manifest := range agentconfig.ZCodeManifests() {
		if name := path.Join(root, manifest); ns.entries[name] != nil {
			return name
		}
	}

	return ""
}

func zcodeMarketplace(ns *namespace, name, requested string) bool {
	if strings.HasSuffix("/"+name, "/"+artifact.ZCodeMarketplaceManifest) {
		return true
	}

	return requested == report.HostZCode && path.Base(name) == "marketplace.json" &&
		capturedJSON(ns.entries[name]).GetOrEmpty("plugins").Kind == jsonconfig.KindArray
}

func zcodeWorkspaceCandidate(ns *namespace, name, requested string) (candidate, bool) {
	root, ok := zcodeWorkspaceRoot(ns, name, requested)
	if !ok || zcodeManifest(ns, root) != "" {
		return candidate{}, false
	}

	return candidate{ns: ns, root: root, host: report.HostZCode, manifest: name, nativeWorkspace: true}, true
}

func zcodeWorkspaceRoot(ns *namespace, name, requested string) (string, bool) {
	if path.Base(name) == artifact.ZCodeRootConfig {
		return path.Dir(name), true
	}

	if root, ok := zcodeKnownRoot(name); ok {
		return root, true
	}

	if requested == report.HostZCode && (name == artifact.ZCodeUserConfig || name == artifact.ZCodeInstalledPlugins) {
		return ".", true
	}

	if root, ok := strings.CutSuffix("/"+name, "/"+artifact.ZCodeSharedMCP); ok {
		root = path.Clean(strings.TrimPrefix(root, "/"))

		return root, requested == report.HostZCode || ns.entries[path.Join(root, artifact.ZCodeDirectory, artifact.ZCodeConfig)] != nil ||
			ns.entries[path.Join(root, artifact.ZCodeRootConfig)] != nil || ns.entries[path.Join(root, artifact.ZCodeDirectory, artifact.ZCodeUserConfig)] != nil
	}

	if requested == report.HostZCode && path.Dir(name) == "." {
		return ".", zcodeStandaloneInput(ns.entries[name], name, len(ns.names) == 1)
	}

	return "", false
}

func zcodeKnownRoot(name string) (string, bool) {
	for _, file := range []string{artifact.ZCodeConfig, artifact.ZCodeUserConfig, artifact.ZCodeInstalledPlugins, "AGENTS.md"} {
		if root, ok := strings.CutSuffix("/"+name, "/"+path.Join(artifact.ZCodeDirectory, file)); ok {
			return path.Clean(strings.TrimPrefix(root, "/")), true
		}
	}

	return workspaceDirectory(name, artifact.ZCodeDirectory, "skills", "agents", "commands")
}

func zcodeStandaloneInput(e *entry, name string, single bool) bool {
	switch name {
	case artifact.ZCodeConfig, artifact.MCPConfig, "mcp.json", "hooks.json", path.Base(artifact.ZCodeInstalledPlugins), "AGENTS.md":
		return true
	}

	if !single || path.Ext(name) != ".json" || name == "plugin.json" || name == "package.json" {
		return false
	}

	root := capturedJSON(e)
	if root.Get("mcpServers") != nil {
		return true
	}

	for hook := range agentconfig.ZCodeHooks(root) {
		if hook.Launch != nil {
			return true
		}
	}

	return false
}

func (p *plugin) discoverZCodePackage() {
	n := p.object(p.manifest)
	if n != nil {
		p.validateManifest(n)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.directory(fieldSkills, "skills", n, report.ComponentSkill, false)
	p.directory(fieldAgents, "agents", n, componentAgent, true)
	p.directory(fieldCommands, "commands", n, componentCommand, true)
	p.configs(fieldHooks, defaultHooksPath, report.ComponentHookConfig, n)
	p.configs(fieldMCPServers, artifact.MCPConfig, report.ComponentMCPConfig, n)
	p.discoverExtensions(n)
}

func (p *plugin) zcodeWorkspace() {
	nativeMCP := false
	for _, file := range []string{artifact.ZCodeRootConfig, path.Join(artifact.ZCodeDirectory, artifact.ZCodeConfig), path.Join(artifact.ZCodeDirectory, artifact.ZCodeUserConfig)} {
		nativeMCP = p.zcodeRuntimeConfig(p.entry(file)) || nativeMCP
	}

	localDirectory := p.b.r.RequestedHost == report.HostZCode && p.root == "." &&
		(p.entry(artifact.ZCodeConfig) != nil || p.entry(artifact.ZCodeUserConfig) != nil || p.entry(artifact.ZCodeInstalledPlugins) != nil)
	if localDirectory {
		nativeMCP = p.zcodeRuntimeConfig(p.entry(artifact.ZCodeConfig)) || nativeMCP
		nativeMCP = p.zcodeRuntimeConfig(p.entry(artifact.ZCodeUserConfig)) || nativeMCP
		p.zcodeInstalled(p.entry(artifact.ZCodeInstalledPlugins))
		p.zcodeAssets(".")
	}

	p.defaultNativeConfig(artifact.ZCodeSharedMCP, report.ComponentMCPConfig, nativeMCP)
	p.zcodeStandaloneConfig()
	p.zcodeInstalled(p.entry(path.Join(artifact.ZCodeDirectory, artifact.ZCodeInstalledPlugins)))
	p.zcodeAssets(artifact.ZCodeDirectory)
	p.zcodeAssets(".agents")
	p.zcodeInstructions()
}

func (p *plugin) zcodeStandaloneConfig() {
	if path.Dir(p.manifest.name) != p.root {
		return
	}

	name := path.Base(p.manifest.name)
	switch name {
	case artifact.MCPConfig, "mcp.json":
		p.defaultNativeConfig(name, report.ComponentMCPConfig, false)
	case path.Base(artifact.ZCodeInstalledPlugins):
		p.zcodeInstalled(p.manifest)
	case artifact.ZCodeRootConfig, artifact.ZCodeConfig, "AGENTS.md":
	default:
		if capturedJSON(p.manifest).Get("mcpServers") != nil {
			p.defaultNativeConfig(name, report.ComponentMCPConfig, false)
		} else {
			p.defaultNativeConfig(name, report.ComponentHookConfig, false)
		}
	}
}

func (p *plugin) zcodeRuntimeConfig(e *entry) bool {
	n := p.object(e)

	mcp := agentconfig.ZCodeMCP(n)
	if mcp != nil {
		p.configFile(e, report.ComponentMCPConfig, p.activation, basisConfiguration, whole(e))
	}

	if agentconfig.ZCodeRuntimeHooks(n) {
		p.configFile(e, report.ComponentHookConfig, p.activation, basisConfiguration, whole(e))
	}

	return agentconfig.ZCodeHasMCP(mcp)
}

func (p *plugin) zcodeInstalled(e *entry) {
	n := p.object(e)
	for i, item := range n.GetOrEmpty("plugins").Elements {
		if !p.b.step() {
			return
		}

		if id, ok := item.Get("id").Text(); ok && id != "" {
			s := ref(e, item.Span)
			p.component(componentExtension, e, activationUnknown, basisSettings, s, "installed:"+strconv.Itoa(i))
		}
	}
}

func (p *plugin) zcodeAssets(base string) {
	for _, item := range []struct{ dir, kind string }{{"skills", report.ComponentSkill}, {"commands", componentCommand}, {"agents", componentAgent}} {
		if base == ".agents" && item.kind == componentAgent {
			continue
		}

		p.selectFiles(path.Join(base, item.dir), item.kind, p.activation, selectionHostDefault, nil, false)
	}
}

func (p *plugin) zcodeInstructions() {
	for _, file := range []string{"AGENTS.md", path.Join(artifact.ZCodeDirectory, "AGENTS.md")} {
		if e := p.entry(file); e != nil {
			p.component(componentRule, e, p.activation, selectionHostDefault, whole(e), "instructions")
		}
	}
}

func (p *plugin) zcodeHooks(e *entry, n *jsonconfig.Node, parent, activation string) {
	ordinal := 0

	for hook := range agentconfig.ZCodeHooks(n) {
		if !p.b.step() {
			return
		}

		if hook.Launch == nil {
			p.issue(issuePluginHooksInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		state := activation
		if hook.Disabled {
			state = activationInactiveForProfile
		}

		s := ref(e, hook.Node.Span)
		id := p.component(report.ComponentHook, e, state, basisConfiguration, s, strconv.Itoa(ordinal))
		p.b.edge(parent, id, relationRegisters, basisConfiguration, state, s)
		p.command(id, hook.Launch.String, hook.Args, hook.Process, s, state, true)

		ordinal++
	}
}
