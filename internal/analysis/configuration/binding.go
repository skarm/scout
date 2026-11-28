package configuration

import (
	"context"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/report"
)

// Bind supplies only immutable captured scope facts, not filesystem or
// network access. The four LP rules share one bounded discovery pass per scan.
func Bind(ctx context.Context, checks []check.Analyzer, docs []document.File, extraction report.ExtractionReport) []check.Analyzer {
	hooks := hookpolicy.Bind(ctx, docs, extraction)

	checks = append([]check.Analyzer(nil), checks...)
	for i, a := range checks {
		switch v := a.(type) {
		case agentConfigCheck:
			v.hooks = hooks
			checks[i] = v
		case bundledSurface:
			v.hooks = hooks
			checks[i] = v
		}
	}

	needed := false

	for _, a := range checks {
		if _, ok := a.(permissionCheck); ok {
			needed = true
			break
		}
	}

	if !needed {
		return checks
	}

	records, failed := permissionRecords(ctx, docs, extraction)

	out := append([]check.Analyzer(nil), checks...)
	for i, a := range out {
		if p, ok := a.(permissionCheck); ok {
			p.records, p.failure = records, failed
			out[i] = p
		}
	}

	return out
}
