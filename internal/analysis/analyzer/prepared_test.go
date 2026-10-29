package analyzer_test

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

// prepared keeps fixtures on the same preparation boundary as production.
func prepared(ctx context.Context, input any) document.File {
	switch value := input.(type) {
	case document.File:
		return analyzer.PrepareDerived(ctx, []document.File{value})[0]
	case artifact.File:
		return analyzer.PrepareDerived(ctx, document.PrepareAll(ctx, []artifact.File{value}))[0]
	default:
		panic("unsupported analysis fixture")
	}
}
