package supplychain

import (
	"context"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/source"
)

// SourceConsumers counts the shared declaration prepass once when its rule is selected.
func SourceConsumers(checks []check.Analyzer) int {
	for _, a := range checks {
		if _, ok := a.(sourceRedirection); ok {
			return 1
		}
	}

	return 0
}

// PrepareSources records source declarations and prepares derived configuration
// documents with the caller's shared parser and operation budgets. The caller
// enables the pass when SourceConsumers returns a nonzero count.
func PrepareSources(ctx context.Context, checks []check.Analyzer, docs []document.File, candidates int) ([]document.File, []check.Analyzer) {
	out := append([]document.File(nil), docs...)
	facts := make(map[string]*check.Facts, len(docs))
	remaining := candidates

	for i, d := range out {
		var inputs []document.DerivedInput

		observations := check.NewFacts(remaining)
		seen := map[source.Span]bool{}
		limited := shell.SourceDeclarations(ctx, d, func(at source.Span) {
			if !seen[at] {
				seen[at] = true
				observations.Add(check.Match{Start: at.Start, End: at.End})
			}
		}, func(found []document.DerivedInput) { inputs = append(inputs, found...) })
		observations.Finish(ctx.Err(), limited)
		remaining -= observations.MatchCount()
		facts[d.Artifact().Metadata().Path] = observations
		out[i] = d.WithDerivedInputs(ctx, inputs, limited)
	}

	bound := append([]check.Analyzer(nil), checks...)
	for i, a := range bound {
		if v, ok := a.(sourceRedirection); ok {
			v.declarations = facts
			bound[i] = v
		}
	}

	return out, bound
}
