package harness

import (
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

const (
	componentRule      = "rule"
	componentTool      = "tool"
	componentExtension = "extension"
)

func nativeWorkspaceCandidate(ns *namespace, name, requested string) (candidate, bool) {
	root, host := nativeWorkspace(name, requested)
	if host == "" && path.Ext(name) == ".json" && hasNativeHooks(ns.entries[name]) {
		root, host = copilotHookWorkspace(name, requested, len(ns.names) == 1)
	}

	switch host {
	case "":
		return candidate{}, false
	case report.HostCursor:
		if ns.entries[path.Join(root, artifact.CursorPluginManifest)] != nil || requested == host && portableManifestAt(ns, root) {
			return candidate{}, false
		}
	case report.HostCopilotCLI:
		if (copilotMarker(ns, root) || requested == host) && copilotManifest(ns, root) != "" {
			return candidate{}, false
		}
	}

	return candidate{ns: ns, root: root, host: host, manifest: name, nativeWorkspace: true}, true
}

func hasNativeHooks(e *entry) bool {
	return capturedJSON(e).Get(fieldHooks) != nil
}

func copilotHookWorkspace(name, requested string, standalone bool) (string, string) {
	for _, file := range []string{agentconfig.CopilotProjectSettings, agentconfig.CopilotProjectLocalSettings} {
		if root, ok := strings.CutSuffix("/"+name, "/"+file); ok {
			return path.Clean(strings.TrimPrefix(root, "/")), report.HostCopilotCLI
		}
	}

	if standalone && requested == report.HostCopilotCLI {
		return path.Dir(name), report.HostCopilotCLI
	}

	return "", ""
}

func portableManifestAt(ns *namespace, root string) bool {
	return agentplugins.ManifestVersion(capturedJSON(ns.entries[path.Join(root, agentplugins.ManifestFile)])) != ""
}

func nativeWorkspace(name, requested string) (root, host string) {
	dir, file := path.Dir(name), path.Base(name)
	if agentconfig.OpenCodeConfigFile(file) {
		if path.Base(dir) == agentconfig.OpenCodeDirectory {
			dir = path.Dir(dir)
		}

		return dir, report.HostOpenCode
	}

	if root, ok := workspaceDirectory(name, agentconfig.OpenCodeDirectory, "agents", "commands", "skills", "plugins", "tools"); ok {
		return root, report.HostOpenCode
	}

	if root, ok := workspaceDirectory(name, agentconfig.CursorDirectory, "mcp.json", "hooks.json", "agents", "commands", "skills", "rules"); ok {
		return root, report.HostCursor
	}

	if root, ok := workspaceDirectory(name, ".github", "mcp.json", "hooks", "agents", "skills"); ok {
		return root, report.HostCopilotCLI
	}
	// Shared configuration basenames require operator-selected context.
	if requested == report.HostCursor && dir == "." && (file == "mcp.json" || file == "hooks.json") {
		return dir, report.HostCursor
	}

	if requested == report.HostCopilotCLI && (file == artifact.MCPConfig || dir == "." && (file == agentconfig.CopilotUserMCP || file == "hooks.json")) {
		return dir, report.HostCopilotCLI
	}

	return "", ""
}

func workspaceDirectory(name, directory string, entries ...string) (string, bool) {
	parts := strings.Split(name, "/")
	for i := range len(parts) - 1 {
		if parts[i] == directory && slices.Contains(entries, parts[i+1]) {
			return path.Clean(strings.Join(parts[:i], "/")), true
		}
	}

	return "", false
}

func (p *plugin) nativePaths() bool {
	return p.host == report.HostCursor || p.host == report.HostCopilotCLI
}

func (p *plugin) discoverNativePackage() {
	root := p.object(p.manifest)
	if root != nil {
		p.validateManifest(root)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.directory(fieldSkills, "skills", root, report.ComponentSkill, false)
	p.directory(fieldAgents, "agents", root, componentAgent, true)
	p.directory(fieldCommands, "commands", root, componentCommand, true)

	if p.host == report.HostCursor {
		p.directory("rules", "rules", root, componentRule, true)
		p.configs(fieldHooks, defaultHooksPath, report.ComponentHookConfig, root)
		p.configs(fieldMCPServers, "mcp.json", report.ComponentMCPConfig, root)
	} else {
		p.rootSkill(root)
		p.configs(fieldHooks, "hooks.json", report.ComponentHookConfig, root)
		p.defaultNativeConfig(defaultHooksPath, report.ComponentHookConfig, root.Get(fieldHooks) != nil)
		p.configs(fieldMCPServers, artifact.MCPConfig, report.ComponentMCPConfig, root)
		p.defaultNativeConfig(agentconfig.CopilotProjectMCP, report.ComponentMCPConfig, false)
		p.configs(fieldLSPServers, "lsp.json", componentLSPConfig, root)
		p.defaultNativeConfig(".github/lsp.json", componentLSPConfig, false)
	}

	p.discoverExtensions(root)
}

func (p *plugin) defaultNativeConfig(name, kind string, inactive bool) {
	if e := p.entry(name); e != nil {
		activation := p.activation
		if inactive {
			activation = activationInactiveForProfile
		}

		p.configFile(e, kind, activation, selectionHostDefault, whole(e))
	}
}

func (p *plugin) portableCopilot() {
	for _, item := range []struct{ dir, kind string }{{"agents", componentAgent}, {"commands", componentCommand}, {"rules", componentRule}} {
		p.selectFiles(path.Join(agentconfig.CopilotExtension, item.dir), item.kind, p.activation, selectionHostDefault, nil, false)
	}

	p.defaultNativeConfig(path.Join(agentconfig.CopilotExtension, defaultHooksPath), report.ComponentHookConfig, false)
	p.defaultNativeConfig(path.Join(agentconfig.CopilotExtension, "lsp.json"), componentLSPConfig, false)
}

func (p *plugin) discoverNativeWorkspace() {
	p.issue(issuePluginHostConfigurationUnverified, p.manifestPath(), report.OutcomePartial)

	switch p.host {
	case report.HostCursor:
		p.cursorWorkspace()
	case report.HostCopilotCLI:
		p.copilotWorkspace()
	case report.HostOpenCode:
		p.openCodeWorkspace()
	}
}

func (p *plugin) cursorWorkspace() {
	p.defaultNativeConfig(agentconfig.CursorProjectMCP, report.ComponentMCPConfig, false)
	p.defaultNativeConfig(agentconfig.CursorProjectHooks, report.ComponentHookConfig, false)

	if path.Dir(p.manifest.name) == p.root {
		switch path.Base(p.manifest.name) {
		case "mcp.json":
			p.defaultNativeConfig("mcp.json", report.ComponentMCPConfig, false)
		case "hooks.json":
			p.defaultNativeConfig("hooks.json", report.ComponentHookConfig, false)
		}
	}

	for _, kind := range []struct{ dir, component string }{{"agents", componentAgent}, {"rules", componentRule}, {"commands", componentCommand}, {"skills", report.ComponentSkill}} {
		p.selectFiles(path.Join(agentconfig.CursorDirectory, kind.dir), kind.component, p.activation, selectionHostDefault, nil, false)
	}
}

func (p *plugin) copilotWorkspace() {
	for _, file := range []string{artifact.MCPConfig, agentconfig.CopilotProjectMCP, agentconfig.CopilotUserMCP} {
		p.defaultNativeConfig(file, report.ComponentMCPConfig, false)
	}

	for _, file := range []string{agentconfig.CopilotProjectSettings, agentconfig.CopilotProjectLocalSettings} {
		if hasNativeHooks(p.entry(file)) {
			p.defaultNativeConfig(file, report.ComponentHookConfig, false)
		}
	}

	if p.manifest.name == path.Join(p.root, "hooks.json") {
		p.defaultNativeConfig("hooks.json", report.ComponentHookConfig, false)
	} else if len(p.ns.names) == 1 && path.Dir(p.manifest.name) == p.root && p.manifest.name != artifact.MCPConfig && p.manifest.name != agentconfig.CopilotUserMCP {
		if hasNativeHooks(p.manifest) {
			p.defaultNativeConfig(path.Base(p.manifest.name), report.ComponentHookConfig, false)
		}
	}

	for _, name := range p.ns.descendants(path.Join(p.root, agentconfig.CopilotProjectHooks)) {
		if !p.b.step() {
			return
		}

		if path.Ext(name) == ".json" && path.Dir(name) == path.Join(p.root, agentconfig.CopilotProjectHooks) {
			p.defaultNativeConfig(path.Join(agentconfig.CopilotProjectHooks, path.Base(name)), report.ComponentHookConfig, false)
		}
	}

	p.selectFiles(".github/agents", componentAgent, p.activation, selectionHostDefault, nil, false)
	p.selectFiles(".github/skills", report.ComponentSkill, p.activation, selectionHostDefault, nil, false)
}
