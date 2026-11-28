package harness

import (
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/report"
)

func (p *plugin) discoverGeminiExtension() {
	manifest := p.object(p.manifest)
	name, _ := manifest.Get("name").Text()
	version, _ := manifest.Get("version").Text()

	if !validName(name) || version == "" {
		p.issue("plugin_hook_manifest_unverified", p.manifestPath(), report.OutcomePartial)
	}

	p.issue("plugin_loader_semantics_limited", p.manifestPath(), report.OutcomePartial)

	if e := p.entry("hooks/hooks.json"); e != nil {
		if p.b.hookTracer != nil && e.Doc != nil {
			*e.Doc = e.Doc.WithGeminiHookShell(p.b.ctx)
		}

		p.configFile(e, report.ComponentHookConfig, p.activation, "host_default", whole(e))
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
