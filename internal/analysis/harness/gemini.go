package harness

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func geminiWorkspaceRoot(name, requested string) (string, bool) {
	if root, ok := artifact.GeminiSettingsRoot(name, requested); ok {
		return root, true
	}

	if root, ok := workspaceDirectory(name, artifact.GeminiDirectory, "agents", "commands", "skills", "policies", agentconfig.GeminiContext); ok {
		return root, true
	}

	return path.Dir(name), path.Base(name) == agentconfig.GeminiContext
}

func (p *plugin) discoverGeminiExtension() {
	manifest := p.object(p.manifest)
	name, _ := manifest.Get(fieldName).Text()
	version, _ := manifest.Get(fieldVersion).Text()

	if !agentconfig.ValidNamedExtension(name, version) {
		p.issue(issuePluginHookManifestUnverified, p.manifestPath(), report.OutcomePartial)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)
	p.geminiMCP(p.manifest, manifest)
	p.geminiAssets(".")
	p.extensionContexts(manifest.Get(agentconfig.ExtensionContextField), agentconfig.GeminiContext)

	if e := p.entry(defaultHooksPath); e != nil {
		p.geminiHookFile(e)
	}
}

func (p *plugin) geminiWorkspace() {
	p.extensionContext(agentconfig.GeminiContext, nil)
	p.extensionContext(path.Join(artifact.GeminiDirectory, agentconfig.GeminiContext), nil)
	p.geminiAssets(artifact.GeminiDirectory)
	p.geminiSettingsFile(p.entry(path.Join(artifact.GeminiDirectory, artifact.GeminiSettings)))

	if _, standalone := artifact.GeminiSettingsRoot(p.manifest.name, p.b.r.RequestedHost); standalone && path.Dir(p.manifest.name) == "." {
		p.geminiSettingsFile(p.entry(artifact.GeminiSettings))
		p.geminiSettingsFile(p.entry(artifact.GeminiSystemDefaults))
		p.geminiAssets(".")
	}
}

func (p *plugin) geminiSettingsFile(e *entry) {
	if e == nil {
		return
	}

	n := p.object(e)
	p.geminiMCP(e, n)

	if n.Get(fieldHooks) != nil {
		p.geminiHookFile(e)
	}
}

func (p *plugin) geminiMCP(e *entry, n *jsonconfig.Node) {
	if servers := n.Get(fieldMCPServers); servers != nil {
		s := ref(e, servers.Span)
		parent := p.component(report.ComponentMCPConfig, e, p.activation, basisConfiguration, s, "gemini-mcp")
		p.b.edge(p.rootNode, parent, relationDeclares, basisConfiguration, p.activation, s)
		p.servers(e, n, report.ComponentMCPConfig, parent, p.activation)
	}
}

func (p *plugin) geminiHookFile(e *entry) {
	if p.b.hookTracer != nil && e.Doc != nil {
		*e.Doc = e.Doc.WithGeminiHookShell(p.b.ctx)
	}

	p.configFile(e, report.ComponentHookConfig, p.activation, selectionHostDefault, whole(e))
}

func (p *plugin) geminiAssets(dir string) {
	p.selectFiles(path.Join(dir, "agents"), componentAgent, p.activation, selectionHostDefault, nil, false)
	p.selectFiles(path.Join(dir, "commands"), componentCommand, p.activation, selectionHostDefault, nil, false)
	p.selectFiles(path.Join(dir, "policies"), componentRule, p.activation, selectionHostDefault, nil, false)

	root := path.Join(p.root, dir, "skills")
	for _, name := range p.ns.descendants(root) {
		if !p.b.step() {
			return
		}

		if path.Base(name) == artifact.SkillManifest && (path.Dir(name) == root || path.Dir(path.Dir(name)) == root) {
			p.selectedFile(name, root, report.ComponentSkill, p.activation, selectionHostDefault, nil)
		}
	}
}

func (p *plugin) extensionContexts(n *jsonconfig.Node, fallback string) {
	if n == nil {
		p.extensionContext(fallback, nil)
		return
	}

	for _, item := range pathValues(n) {
		if !p.b.step() {
			return
		}

		s := ref(p.manifest, item.Span)
		raw, _ := item.Text()

		rel, reason := artifactpath.Reference(raw, false)
		if reason != "" || rel == "." {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
			continue
		}

		p.extensionContext(rel, s)
	}
}

func (p *plugin) extensionContext(name string, declaration *report.SourceRef) {
	if e := p.entry(name); e != nil {
		salt := "qwen-context"
		if p.host == report.HostGeminiCLI {
			salt = "gemini-context"
		}

		id := p.component(componentRule, e, p.activation, basisConfiguration, whole(e), salt)
		if declaration != nil {
			p.b.edge(p.rootNode, id, relationDeclares, basisManifest, p.activation, declaration)
		}
	} else if declaration != nil {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", declaration)
	}
}

func (p *plugin) extensionMCPOperand(candidate string) (string, bool) {
	if p.nativeWorkspace || p.portable != "" {
		return "", false
	}

	switch p.host {
	case report.HostGeminiCLI:
		return strings.CutPrefix(candidate, agentconfig.ExtensionPath+"/")
	case report.HostQwenCode:
		return agentconfig.QwenExtensionOperand(candidate)
	default:
		return "", false
	}
}

func (p *plugin) linkGeminiHandler(paths []hooktrace.Path, id, activation string, s *report.SourceRef) bool {
	for _, trace := range paths {
		if e := p.ns.entries[trace.Target]; e != nil && len(trace.Steps) == 1 {
			p.capturedHandler(id, e, activation, s)
			return true
		}
	}

	return false
}
