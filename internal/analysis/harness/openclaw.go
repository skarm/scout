package harness

import (
	"path"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func openClawPackageCandidate(ns *namespace, file string) bool {
	root := path.Dir(file)
	if ns.entries[path.Join(root, artifact.OpenClawManifest)] != nil {
		return false
	}

	return agentconfig.OpenClawPackageDeclared(capturedJSON(ns.entries[file]).Get(agentconfig.OpenClawPackageKey))
}

func openClawStandaloneHook(ns *namespace, name, requested string) bool {
	dir := path.Dir(name)
	if requested != report.HostOpenClaw && (dir == "." || path.Base(path.Dir(dir)) != "hooks") {
		found := false

		for _, handler := range agentconfig.OpenClawHookHandlers() {
			if ns.entries[path.Join(dir, handler)] != nil {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	// A hook in a native package belongs to its package declaration.
	for root := dir; ; root = path.Dir(root) {
		if ns.entries[path.Join(root, artifact.OpenClawManifest)] != nil || openClawPackageCandidate(ns, path.Join(root, "package.json")) {
			return false
		}

		if root == "." {
			return true
		}
	}
}

func (p *plugin) openClawWorkspace() {
	e := p.manifest
	if path.Base(e.name) == artifact.OpenClawHookManifest {
		p.openClawHook(e, nil)
		return
	}

	n := p.object(e)
	p.openClawMCP(e, n.Get("mcp").Get("servers"))

	for include := range agentconfig.OpenClawIncludes(p.b.ctx, n) {
		if !p.b.step() {
			return
		}

		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, "openclaw_config_include_unresolved", "", ref(e, include.Span))
	}
}

func (p *plugin) openClawMCP(e *entry, servers *jsonconfig.Node) {
	if servers == nil {
		return
	}

	s := ref(e, servers.Span)
	parent := p.component(report.ComponentMCPConfig, e, p.activation, basisConfiguration, s, "openclaw-mcp")
	p.b.edge(p.rootNode, parent, relationDeclares, basisConfiguration, p.activation, s)

	if servers.Kind != jsonconfig.KindObject {
		p.issue(issuePluginServerMapInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, server := range servers.Members {
		if !p.b.step() {
			return
		}

		activation := p.activation
		if enabled := server.Value.Get("enabled"); enabled != nil && enabled.Kind == jsonconfig.KindBool && !enabled.Bool {
			activation = activationInactiveForProfile
		}

		p.serverEntry(e, server.Value, report.ComponentMCPConfig, parent, activation, i)
	}
}

func (p *plugin) discoverOpenClawPackage() {
	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)

	if path.Base(p.manifest.name) == artifact.OpenClawManifest {
		n := p.object(p.manifest)
		if _, ok := agentconfig.OpenClawPluginID(n); !ok {
			p.issue(issuePluginMetadataTypeInvalid, p.manifestPath(), formatInvalid)
		}

		p.openClawPathList(p.manifest, n.Get(fieldSkills), func(rel string, declaration *report.SourceRef) {
			p.selectFiles("./"+rel, report.ComponentSkill, p.activation, basisManifest, declaration, true)
		})
	}

	if e := p.entry("package.json"); e != nil {
		p.openClawPackageMetadata(e, p.object(e).Get(agentconfig.OpenClawPackageKey))
	}
}

func (p *plugin) openClawPackageMetadata(e *entry, n *jsonconfig.Node) {
	for _, field := range []string{"extensions", "runtimeExtensions"} {
		p.openClawPathList(e, n.Get(field), p.openClawEntry)
	}

	for _, field := range []string{"setupEntry", "runtimeSetupEntry"} {
		if item := n.Get(field); item != nil {
			p.openClawPath(e, item, p.openClawEntry)
		}
	}

	p.openClawPathList(e, n.Get("hooks"), func(rel string, declaration *report.SourceRef) {
		if e := p.entry(path.Join(rel, artifact.OpenClawHookManifest)); e != nil {
			p.openClawHook(e, declaration)
		} else {
			p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", declaration)
		}
	})
}

func (p *plugin) openClawPathList(e *entry, list *jsonconfig.Node, collect func(string, *report.SourceRef)) {
	if list == nil {
		return
	}

	if list.Kind != jsonconfig.KindArray {
		p.issue(issuePluginConfigShapeInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for _, item := range list.Elements {
		if !p.b.step() {
			return
		}

		p.openClawPath(e, item, collect)
	}
}

func (p *plugin) openClawPath(e *entry, item *jsonconfig.Node, collect func(string, *report.SourceRef)) {
	s := ref(e, item.Span)
	raw, _ := item.Text()

	rel, reason := artifactpath.Reference(raw, false)
	if reason != "" {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reason, "", s)
		return
	}

	collect(rel, s)
}

func (p *plugin) openClawEntry(name string, declaration *report.SourceRef) {
	e := p.entry(name)
	if e == nil || e.Doc == nil {
		p.reference(p.rootNode, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", declaration)
		return
	}

	p.capturedHandler(p.rootNode, e, p.activation, declaration)
}

func (p *plugin) openClawHook(e *entry, declaration *report.SourceRef) {
	id := p.component(report.ComponentHook, e, p.activation, basisConfiguration, whole(e), "openclaw-hook")
	if declaration == nil {
		declaration = whole(e)
	}

	p.b.edge(p.rootNode, id, relationRegisters, basisConfiguration, p.activation, declaration)

	for _, file := range agentconfig.OpenClawHookHandlers() {
		candidate := p.ns.entries[path.Join(path.Dir(e.name), file)]
		if candidate == nil {
			continue
		}

		if candidate.Doc != nil {
			p.capturedHandler(id, candidate, p.activation, declaration)
			return
		}

		break
	}

	p.reference(id, referenceKindHandler, report.ReferenceUnresolved, report.ReferenceReasonHandlerNotCaptured, "", declaration)
}
