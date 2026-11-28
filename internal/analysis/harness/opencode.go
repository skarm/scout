package harness

import (
	"fmt"
	"path"
	"strings"

	"github.com/skarm/scout/internal/agentconfig"
	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func (p *plugin) openCodeWorkspace() {
	for _, base := range []string{".", agentconfig.OpenCodeDirectory} {
		for _, file := range []string{agentconfig.OpenCodeConfig, agentconfig.OpenCodeConfigJSONC} {
			if e := p.entry(path.Join(base, file)); e != nil {
				p.openCodeConfig(e)
			}
		}
	}

	for _, item := range []struct{ dir, kind string }{{"agents", componentAgent}, {"commands", componentCommand}, {"skills", report.ComponentSkill}} {
		p.selectFiles(path.Join(agentconfig.OpenCodeDirectory, item.dir), item.kind, p.activation, selectionHostDefault, nil, false)
	}

	p.openCodeScriptDirectory(path.Join(agentconfig.OpenCodeDirectory, "plugins"), componentExtension)
	p.openCodeScriptDirectory(path.Join(agentconfig.OpenCodeDirectory, "tools"), componentTool)
}

func (p *plugin) openCodeConfig(e *entry) {
	n := p.object(e)
	if n == nil {
		return
	}

	if servers, _ := agentconfig.OpenCodeMCPMap(n); servers != nil {
		p.openCodeMCP(e, servers)
	}

	for _, field := range []string{"plugins", "plugin"} {
		if list := n.Get(field); list != nil {
			p.openCodePluginList(e, field, list)
		}
	}
}

func (p *plugin) openCodeMCP(e *entry, servers *jsonconfig.Node) {
	parent := p.component(report.ComponentMCPConfig, e, p.activation, basisConfiguration, ref(e, servers.Span), "opencode-mcp")
	if servers.Kind != jsonconfig.KindObject {
		p.issue(issuePluginServerMapInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, server := range servers.Members {
		if !p.b.step() {
			return
		}

		activation := p.activation
		if enabled, declared := agentconfig.OpenCodeServerEnabled(server.Value); declared && !enabled {
			activation = activationInactiveForProfile
		}

		s := ref(e, server.Value.Span)
		id := p.component("mcp_server", e, activation, basisConfiguration, s, fmt.Sprintf("opencode-mcp:%d", i))
		p.b.edge(parent, id, relationDeclares, basisConfiguration, activation, s)

		if !agentconfig.OpenCodeServerValid(server.Value) {
			p.issue(issuePluginServerInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		if command := server.Value.Get(fieldCommand); command != nil {
			args, _ := stringValues(command)
			p.nativeCommand(id, args, server.Value.Get("cwd"), ref(e, command.Span), activation)
		}

		if url := server.Value.Get(fieldURL); url != nil {
			p.reference(id, referenceKindRemoteEndpoint, report.ReferenceUnresolved, reasonRemoteImplementationNotScanned, "", ref(e, url.Span))
		}
	}
}

func (p *plugin) openCodePluginList(e *entry, field string, list *jsonconfig.Node) {
	if list.Kind != jsonconfig.KindArray {
		p.issue(issuePluginConfigShapeInvalid, e.Meta.Path, formatInvalid)
		return
	}

	for i, item := range list.Elements {
		if !p.b.step() {
			return
		}

		value := agentconfig.OpenCodePluginValue(item)

		raw, ok := value.Text()
		if !ok || raw == "" {
			p.issue(issuePluginConfigShapeInvalid, e.Meta.Path, formatInvalid)
			continue
		}

		s := ref(e, value.Span)
		if strings.HasPrefix(raw, "-") {
			p.component(componentExtension, e, activationInactiveForProfile, basisConfiguration, s, fmt.Sprintf("%s:%d", field, i))
			continue
		}

		id := p.component(componentExtension, e, p.activation, basisConfiguration, s, fmt.Sprintf("%s:%d", field, i))
		p.openCodePluginReference(e, id, raw, s)
	}
}

func (p *plugin) openCodePluginReference(e *entry, id, raw string, s *report.SourceRef) {
	if !strings.HasPrefix(raw, "./") {
		p.reference(id, referenceKindDependency, report.ReferenceUnresolved, reasonExternalDependencyNotMaterialized, "", s)
		return
	}

	rel, reason := artifactpath.Reference(raw, true)
	if reason != "" || rel == "." {
		p.reference(id, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingOrUnsupportedComponent, "", s)
		return
	}

	name := path.Join(path.Dir(e.name), rel)

	target := p.openCodePackageSource(name)
	if target == nil {
		p.reference(id, referenceKindComponentPath, report.ReferenceUnresolved, reasonMissingComponent, "", s)
		return
	}

	targetID := p.openCodeExtension(target)
	p.b.edge(id, targetID, relationDeclares, basisConfiguration, p.activation, s)
	p.reference(id, referenceKindComponentPath, report.ReferenceResolved, reasonCapturedFile, targetID, s)
}

func (p *plugin) openCodeScriptDirectory(dir, kind string) {
	base := path.Join(p.root, dir)
	for _, name := range p.ns.descendants(base) {
		if !p.b.step() {
			return
		}

		parent := path.Dir(name)
		if parent == base && agentconfig.OpenCodeScript(name) {
			if kind == componentExtension {
				p.openCodeExtension(p.ns.entries[name])
			} else {
				e := p.ns.entries[name]
				p.component(kind, e, p.activation, selectionHostDefault, whole(e), "opencode-script")
			}
		} else if kind == componentExtension && path.Dir(parent) == base && p.openCodeScriptSource(parent) == p.ns.entries[name] {
			p.openCodeExtension(p.ns.entries[name])
		}
	}
}

func (p *plugin) openCodeScriptSource(name string) *entry {
	if agentconfig.OpenCodeScript(name) {
		return p.ns.entries[name]
	}

	return p.openCodePackageSource(name)
}

func (p *plugin) openCodePackageSource(name string) *entry {
	for _, file := range []string{"package.json", "index.ts", "index.js"} {
		if e := p.ns.entries[path.Join(name, file)]; e != nil {
			return e
		}
	}

	return nil
}

func (p *plugin) openCodeExtension(e *entry) string {
	id := p.component(componentExtension, e, p.activation, basisPackageInventory, whole(e), "opencode-script")
	if path.Base(e.name) == "package.json" {
		p.openCodePackageEntry(e, id)
	}

	return id
}

func (p *plugin) openCodePackageEntry(e *entry, id string) {
	n := p.object(e)

	entry := n.Get("exports").Get("./server")
	if entry == nil {
		entry = n.Get("main")
	}

	if raw, ok := entry.Text(); ok {
		rel, reason := artifactpath.Reference(raw, false)
		if reason == "" && rel != "." {
			if file := p.ns.entries[path.Join(path.Dir(e.name), rel)]; file != nil && file.Doc != nil {
				p.capturedHandler(id, file, p.activation, ref(e, entry.Span))
				return
			}
		}
	}

	p.reference(id, referenceKindHandler, report.ReferenceUnresolved, report.ReferenceReasonHandlerNotCaptured, "", whole(e))
}
