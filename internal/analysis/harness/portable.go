package harness

import (
	"fmt"
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	issuePortableVersionUnsupported = "portable_plugin_version_unsupported"
	issuePortableMCPInvalid         = "portable_mcp_config_invalid"
	issuePortableMCPServerInvalid   = "portable_mcp_server_invalid"
	issuePortableHooksInvalid       = "portable_hooks_config_invalid"
)

func (p *plugin) discoverPortable() {
	if p.portable == agentplugins.Unsupported {
		p.issue(issuePortableVersionUnsupported, p.manifestPath(), report.OutcomePartial)
		return
	}

	manifest := p.object(p.manifest)

	metadata := p.portable.ReadManifest(manifest)
	if !metadata.Valid {
		p.issue(issuePluginMetadataTypeInvalid, p.manifestPath(), formatInvalid)
		return
	}

	if metadata.IgnoredFields {
		p.issue(issuePluginUnknownField, p.manifestPath(), report.OutcomePartial)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)

	skills := path.Join(p.root, agentplugins.SkillsDir)
	for _, key := range p.ns.descendants(skills) {
		if !p.b.step() {
			return
		}

		if agentplugins.SkillPath(strings.TrimPrefix(key, skills+"/")) {
			p.selectedFile(key, skills, report.ComponentSkill, p.activation, selectionHostDefault, nil)
		}
	}

	p.portableMCP()

	if p.portable == agentplugins.V1_1 && p.host != report.HostQwenCode {
		p.portableHooks()
	}

	if p.host == report.HostCodex {
		p.portableCodex(manifest)
	}

	if p.host == report.HostCopilotCLI && p.portable == agentplugins.V1_0 {
		p.portableCopilot()
	}

	if p.host != report.HostQwenCode {
		p.discoverHostConfigs()
	}
}

func (p *plugin) portableMCP() {
	e := p.entry(agentplugins.MCPFile)
	if e == nil {
		return
	}

	parent := p.component(report.ComponentMCPConfig, e, p.activation, selectionHostDefault, whole(e), report.ComponentMCPConfig)

	servers := p.portable.MCPServers(p.object(e))
	if servers == nil {
		p.issue(issuePortableMCPInvalid, e.Meta.Path, report.OutcomePartial)
		return
	}

	for i, member := range servers.Members {
		if !p.b.step() {
			return
		}

		if !agentplugins.ValidMCPServer(member.Value) {
			p.issue(issuePortableMCPServerInvalid, e.Meta.Path, report.OutcomePartial)
			continue
		}

		if p.host == report.HostQwenCode && agentconfig.QwenPortableSSE(member.Value) {
			continue
		}

		p.serverEntry(e, member.Value, report.ComponentMCPConfig, parent, p.activation, i)
	}
}

func (p *plugin) portableHooks() {
	e := p.entry(agentplugins.HooksFile)
	if e == nil {
		return
	}

	parent := p.component(report.ComponentHookConfig, e, p.activation, selectionHostDefault, whole(e), report.ComponentHookConfig)

	hooks := p.portable.Hooks(p.object(e))
	if hooks == nil {
		p.issue(issuePortableHooksInvalid, e.Meta.Path, report.OutcomePartial)
		return
	}

	for ei, event := range hooks.Members {
		if !p.b.step() {
			return
		}

		if !agentplugins.ValidHookEvent(event) {
			p.issue(issuePortableHooksInvalid, e.Meta.Path, report.OutcomePartial)
			continue
		}

		for hi, handler := range event.Value.Elements {
			if !p.b.step() {
				return
			}

			if !agentplugins.ValidHook(handler) {
				p.issue(issuePortableHooksInvalid, e.Meta.Path, report.OutcomePartial)
				continue
			}

			s := ref(e, handler.Span)
			id := p.component(report.ComponentHook, e, p.activation, basisConfiguration, s, fmt.Sprintf("portable-hook:%d:%d", ei, hi))
			p.b.edge(parent, id, relationRegisters, basisConfiguration, p.activation, s)

			args, _ := stringValues(handler.Get(fieldArgs))
			p.portableCommand(id, handler.Get(fieldCommand).String, args, s, p.activation)
		}
	}
}

func (p *plugin) portableCommand(id, command string, args []string, s *report.SourceRef, activation string) {
	if !strings.HasPrefix(command, "./") {
		p.command(id, command, args, true, s, activation, false)
		return
	}
	// Portable commands resolve relative to the package root. They are argv
	// declarations even when the executable name contains spaces.
	rel, _ := artifactpath.Reference(command, true)
	if e := p.entry(rel); e != nil && e.Doc != nil {
		p.capturedHandler(id, e, activation, s)
	} else {
		p.reference(id, referenceKindHandler, report.ReferenceUnresolved, report.ReferenceReasonHandlerNotCaptured, "", s)
	}
}

func (p *plugin) portableCodex(manifest *jsonconfig.Node) {
	source, settings := p.manifest, agentplugins.OpenAISettings(manifest)
	if settings == nil {
		if overlay := p.entry(artifact.CodexPluginManifest); overlay != nil {
			source, settings = overlay, p.object(overlay)
			interpretation := &p.b.r.Plugins[p.index]
			interpretation.Manifests = append(interpretation.Manifests, overlay.Meta.Path)
		}
	}

	p.configsFrom(fieldHooks, defaultHooksPath, report.ComponentHookConfig, source, settings.Get(fieldHooks))
	p.configsFrom(fieldApps, ".app.json", componentAppConfig, source, settings.Get(fieldApps))

	if n := settings.Get("onboardingSkill"); n != nil {
		value, ok := n.Text()
		if !ok || path.Base(value) != artifact.SkillManifest {
			p.issue(issuePluginComponentPathTypeInvalid, source.Meta.Path, formatInvalid)
			return
		}

		p.selectFiles(value, report.ComponentSkill, p.activation, basisManifest, ref(source, n.Span), true)
	}
}
