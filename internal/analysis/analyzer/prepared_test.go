package analyzer_test

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/supplychain"
	"github.com/skarm/scout/internal/capture/artifact"
)

// prepared keeps fixtures on the same preparation boundary as production.
func prepared(ctx context.Context, input any) document.File {
	switch value := input.(type) {
	case document.File:
		return prepareDerived(ctx, []document.File{value})[0]
	case artifact.File:
		return prepareDerived(ctx, document.PrepareAll(ctx, []artifact.File{value}))[0]
	default:
		panic("unsupported analysis fixture")
	}
}

func prepareDerived(ctx context.Context, docs []document.File) []document.File {
	out, _ := analyzer.PrepareDerivedWithin(ctx, supplychain.DependencyRules(), docs, 1, 0)
	return out
}
