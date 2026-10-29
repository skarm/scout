package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/report"
)

// BindBundle allocates the bundle prepass its disjoint share of run operations.
func BindBundle(ctx context.Context, checks []Analyzer, docs []document.File, extraction report.ExtractionReport, limit int, operations uint64) []Analyzer {
	return bundle.Bind(phaseQuota(ctx, checks, 1, operations), checks, docs, extraction, limit)
}

func bundleConsumers(checks []Analyzer) int { return bundle.Consumers(checks) }
