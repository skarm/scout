package harness

import (
	"path"
	"strconv"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func (p *plugin) codexWorkspace() {
	p.codexTOML(p.entry(path.Join(artifact.CodexDirectory, artifact.CodexConfig)))

	name := path.Join(p.root, artifact.CodexConfig)
	if _, ok := artifact.CodexTOMLRoot(name, p.b.r.RequestedHost); ok {
		p.codexTOML(p.entry(artifact.CodexConfig))
	}
}

func (p *plugin) codexTOML(e *entry) {
	if p.object(e).Get(fieldMCPServersSnake) != nil {
		p.configFile(e, report.ComponentMCPConfig, p.activation, basisConfiguration, whole(e))
	}
}

func claudeMCPFile(name string) bool {
	return name == artifact.ClaudeGlobalConfig || name == artifact.ClaudeManagedMCP
}

func (p *plugin) claudeWorkspace() {
	global := p.entry(artifact.ClaudeGlobalConfig)
	if n := p.object(global); n != nil {
		p.claudeMCPConfig(global, n)
		p.claudeProjectMCP(global, n.Get("projects"))
	}

	managed := p.entry(artifact.ClaudeManagedMCP)
	p.claudeMCPConfig(managed, p.object(managed))
	p.discoverHostConfig(artifact.ClaudeManagedSettings)
}

func (p *plugin) claudeMCPConfig(e *entry, n *jsonconfig.Node) {
	if n.Get(fieldMCPServers) != nil {
		p.configFile(e, report.ComponentMCPConfig, p.activation, basisConfiguration, whole(e))
	}
}

// Treat the saved project maps as separate declarations inside the same file.
// Project keys stay in source evidence and are never used as filesystem paths.
func (p *plugin) claudeProjectMCP(e *entry, projects *jsonconfig.Node) {
	if projects == nil || projects.Kind != jsonconfig.KindObject {
		return
	}

	for i, project := range projects.Members {
		if !p.b.step() {
			return
		}

		if project.Value.Get(fieldMCPServers) != nil {
			s := ref(e, project.Value.Span)
			id := p.component(report.ComponentMCPConfig, e, activationUnknown, basisSettings, s, "project-mcp:"+strconv.Itoa(i))
			p.servers(e, project.Value, report.ComponentMCPConfig, id, activationUnknown)
		}
	}
}
