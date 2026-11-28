package harness

import (
	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/report"
)

func (p *plugin) discoverGeminiExtension() {
	manifest := p.object(p.manifest)
	name, _ := manifest.Get(fieldName).Text()
	version, _ := manifest.Get(fieldVersion).Text()

	if !validName(name) || version == "" {
		p.issue(issuePluginHookManifestUnverified, p.manifestPath(), report.OutcomePartial)
	}

	p.issue(issuePluginLoaderSemanticsLimited, p.manifestPath(), report.OutcomePartial)

	if e := p.entry(defaultHooksPath); e != nil {
		if p.b.hookTracer != nil && e.Doc != nil {
			*e.Doc = e.Doc.WithGeminiHookShell(p.b.ctx)
		}

		p.configFile(e, report.ComponentHookConfig, p.activation, selectionHostDefault, whole(e))
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
