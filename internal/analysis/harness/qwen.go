package harness

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func qwenPluginProfile(ns *namespace, root, requested string) bool {
	if requested == report.HostQwenCode ||
		requested == report.HostAuto && ns.entries[path.Join(root, agentconfig.QwenManifest)] != nil {
		return true
	}

	extensions := path.Dir(root)

	return path.Base(extensions) == "extensions" && path.Base(path.Dir(extensions)) == artifact.QwenDirectory
}

func qwenWorkspaceCandidate(ns *namespace, name, requested string) (candidate, bool) {
	root, ok := qwenWorkspaceRoot(ns, name, requested)
	if !ok || ns.entries[path.Join(root, agentconfig.QwenManifest)] != nil ||
		requested == report.HostQwenCode && portableManifestAt(ns, root) {
		return candidate{}, false
	}

	return candidate{ns: ns, root: root, host: report.HostQwenCode, manifest: name, nativeWorkspace: true}, true
}

func qwenWorkspaceRoot(ns *namespace, name, requested string) (string, bool) {
	if root, ok := artifact.QwenSettingsRoot(name, requested); ok {
		return root, true
	}

	if root, ok := workspaceDirectory(name, artifact.QwenDirectory, "agents", "commands", "rules", "workflows", "skills", agentconfig.QwenLocalContext, agentconfig.QwenContext); ok {
		return root, true
	}

	dir, file := path.Dir(name), path.Base(name)
	switch file {
	case agentconfig.QwenContext:
		return dir, true
	case "AGENTS.md", artifact.MCPConfig, artifact.QwenLSP:
		return dir, requested == report.HostQwenCode || ns.entries[path.Join(dir, artifact.QwenDirectory, artifact.QwenSettings)] != nil ||
			ns.entries[path.Join(dir, agentconfig.QwenContext)] != nil
	}

	if requested == report.HostQwenCode {
		for _, folder := range []string{"agents", "commands", "rules", "workflows", "skills", ".agents/skills"} {
			if strings.HasPrefix(name, folder+"/") {
				return ".", true
			}
		}

		return dir, dir == "." && file == agentconfig.QwenLocalContext
	}

	return "", false
}

func (p *plugin) qwenWorkspace() {
	p.extensionContext(agentconfig.QwenContext, nil)
	p.extensionContext("AGENTS.md", nil)
	p.extensionContext(path.Join(artifact.QwenDirectory, agentconfig.QwenContext), nil)
	p.extensionContext(path.Join(artifact.QwenDirectory, agentconfig.QwenLocalContext), nil)
	p.qwenWorkspaceAssets(artifact.QwenDirectory)
	p.selectFiles(".agents/skills", report.ComponentSkill, p.activation, selectionHostDefault, nil, false)
	p.qwenMCPFile(p.entry(artifact.MCPConfig))

	if e := p.entry(artifact.QwenLSP); e != nil {
		p.configFile(e, componentLSPConfig, p.activation, selectionHostDefault, whole(e))
	}

	p.qwenSettingsFile(p.entry(path.Join(artifact.QwenDirectory, artifact.QwenSettings)))

	for _, name := range []string{artifact.QwenSettings, artifact.QwenSystemDefaults} {
		if _, ok := artifact.QwenSettingsRoot(path.Join(p.root, name), p.b.r.RequestedHost); ok {
			p.qwenSettingsFile(p.entry(name))
		}
	}

	if p.b.r.RequestedHost == report.HostQwenCode && len(p.ns.descendants(path.Join(p.root, artifact.QwenDirectory))) == 0 {
		p.extensionContext(agentconfig.QwenLocalContext, nil)
		p.qwenWorkspaceAssets(".")
	}
}

func (p *plugin) qwenWorkspaceAssets(base string) {
	for _, item := range []struct{ dir, kind string }{
		{"agents", componentAgent},
		{"commands", componentCommand},
		{"rules", componentRule},
		{"skills", report.ComponentSkill},
		{"workflows", componentWorkflow},
	} {
		p.selectFiles(path.Join(base, item.dir), item.kind, p.activation, selectionHostDefault, nil, false)
	}
}

func (p *plugin) qwenMCPFile(e *entry) {
	if e != nil && p.object(e).Get(fieldMCPServers) != nil {
		p.configFile(e, report.ComponentMCPConfig, p.activation, selectionHostDefault, whole(e))
	}
}

func (p *plugin) qwenSettingsFile(e *entry) {
	if e == nil {
		return
	}

	p.qwenMCPFile(e)

	if n := p.object(e); n.Get(fieldHooks) != nil {
		activation := p.activation
		if disabled := n.Get("disableAllHooks"); disabled != nil && disabled.Kind == jsonconfig.KindBool && disabled.Bool {
			activation = activationInactiveForProfile
		}

		p.configFile(e, report.ComponentHookConfig, activation, selectionHostDefault, whole(e))
	}
}

func (p *plugin) discoverQwenExtension() {
	n := p.object(p.manifest)
	name, _ := n.Get(fieldName).Text()

	version, _ := n.Get(fieldVersion).Text()
	if !agentconfig.ValidNamedExtension(name, version) {
		p.issue(issuePluginHookManifestUnverified, p.manifestPath(), report.OutcomePartial)
		return
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.qwenMCPFile(p.manifest)
	p.qwenExtensionConfig(n.Get(fieldHooks), report.ComponentHookConfig, defaultHooksPath)
	p.qwenExtensionConfig(n.Get(fieldLSPServers), componentLSPConfig, "")
	p.extensionContexts(n.Get(agentconfig.ExtensionContextField), agentconfig.QwenContext)
	p.selectFiles("rules", componentRule, p.activation, selectionHostDefault, nil, false)
	p.qwenExtensionAssets(n)
	p.qwenChannels(n.Get("channels"))
}

func (p *plugin) qwenExtensionConfig(n *jsonconfig.Node, kind, fallback string) {
	if n == nil {
		if fallback != "" {
			if e := p.entry(fallback); e != nil {
				p.configFile(e, kind, p.activation, selectionHostDefault, whole(e))
			}
		}

		return
	}

	if n.Kind == jsonconfig.KindObject {
		p.configFile(p.manifest, kind, p.activation, basisManifest, whole(p.manifest))
		return
	}

	raw, _ := n.Text()
	rel, reason := artifactpath.Reference(raw, false)

	s := ref(p.manifest, n.Span)
	if reason != "" || rel == "." {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
		return
	}

	if e := p.entry(rel); e != nil && e != p.manifest {
		p.configFile(e, kind, p.activation, basisManifest, s)
	} else {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
	}
}

func (p *plugin) qwenExtensionAssets(n *jsonconfig.Node) {
	for _, item := range []struct{ dir, kind string }{
		{"agents", componentAgent}, {"commands", componentCommand}, {"skills", report.ComponentSkill}, {"workflows", componentWorkflow},
	} {
		declared := n.Get(item.dir)
		if declared == nil {
			p.selectFiles(item.dir, item.kind, p.activation, selectionHostDefault, nil, false)
			continue
		}

		for _, value := range pathValues(declared) {
			if !p.b.step() {
				return
			}

			text, _ := value.Text()
			p.selectFiles(text, item.kind, p.activation, basisManifest, ref(p.manifest, value.Span), true)
		}
	}
}

func (p *plugin) qwenChannels(n *jsonconfig.Node) {
	if n == nil {
		return
	}

	for _, channel := range n.Members {
		if !p.b.step() {
			return
		}

		entry := channel.Value.Get("entry")
		raw, _ := entry.Text()
		s := ref(p.manifest, channel.Value.Span)

		rel, reason := artifactpath.Reference(raw, false)
		if reason != "" || rel == "." {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
			continue
		}

		e := p.entry(rel)
		if e == nil {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
			continue
		}

		id := p.component("channel", e, p.activation, basisManifest, whole(e), "entry")
		p.b.edge(p.rootNode, id, relationDeclares, basisManifest, p.activation, s)
	}
}

// qwenLSPSocket records the endpoint declaration without connecting to it.
func (p *plugin) qwenLSPSocket(e *entry, n *jsonconfig.Node, id string) bool {
	transport, _ := n.Get("transport").Text()
	if transport != "tcp" && transport != "socket" {
		return false
	}

	if socket := n.Get("socket"); socket != nil {
		p.reference(id, referenceKindRemoteEndpoint, report.ReferenceUnresolved, reasonRemoteBehaviorUnverified, "", ref(e, socket.Span))
	} else {
		p.issue(issuePluginServerTransportUnverified, e.Meta.Path, report.OutcomePartial)
	}

	return true
}
