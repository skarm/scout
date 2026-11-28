package harness

import (
	"iter"
	"path"

	"github.com/skarm/scout/internal/analysis/hooktrace"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func (p *plugin) traceHook(e *entry, hook *jsonconfig.Node, event, matcher string) []hooktrace.Path {
	if p.host == report.HostGeminiCLI {
		if !hookevent.Gemini(event) {
			p.issue("plugin_hook_event_unverified", e.Meta.Path, report.OutcomePartial)
			return nil
		}
	} else if !hookevent.Known(event) {
		return nil
	}

	paths, limited := p.b.hookTracer.Trace(&e.File, hook, event, matcher, hooktrace.Scope{
		Host: p.host, Inactive: p.activation == "inactive_for_profile",
		ProjectSettings: p.projectSettings, Files: p,
	})
	if limited {
		p.issue("hook_source_command_limit", e.Meta.Path, report.OutcomePartial)
	}

	return paths
}

func (p *plugin) LookupFile(name string) *hooktrace.File {
	if e := p.entry(name); e != nil {
		return &e.File
	}

	return nil
}

// Descendants yields names relative to a directory inside the plugin root.
func (p *plugin) Descendants(dir string) iter.Seq[string] {
	name := path.Join(p.root, dir)

	return func(yield func(string) bool) {
		for _, descendant := range p.ns.descendants(name) {
			if !yield(descendant[len(name)+1:]) {
				break
			}
		}
	}
}
