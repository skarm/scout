package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/source"
)

// PrepareDerived completes source-owned configuration preparation before workers
// start. No check may select a parser or reset a run's aggregate parser budget.
func PrepareDerived(ctx context.Context, docs []document.File) []document.File {
	out, _ := PrepareDerivedWithin(ctx, []Analyzer{sourceRedirection{}}, docs, 1, 0)
	return out
}

func usesDerivedConfigurations(checks []Analyzer) bool {
	for _, analyzer := range checks {
		if _, ok := analyzer.(sourceRedirection); ok {
			return true
		}
	}

	return false
}

func sourceConsumers(checks []Analyzer) int {
	if usesDerivedConfigurations(checks) {
		return 1
	}

	return 0
}

// PrepareDerivedWithin charges the single source-declaration prepass to its
// explicit share of the run's operation quota. The check only projects these
// frozen observations; it never walks the same source a second time.
func PrepareDerivedWithin(ctx context.Context, checks []Analyzer, docs []document.File, candidates int, operations uint64) ([]document.File, []Analyzer) {
	if !usesDerivedConfigurations(checks) {
		return docs, checks
	}

	ctx = phaseQuota(ctx, checks, 1, operations)

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
				observations.Add(Match{Start: at.Start, End: at.End})
			}
		}, func(found []document.DerivedInput) { inputs = append(inputs, found...) })
		observations.Finish(ctx.Err(), limited)
		remaining -= observations.MatchCount()
		facts[d.Artifact().Metadata().Path] = observations
		out[i] = d.WithDerivedInputs(ctx, inputs, limited)
	}

	bound := append([]Analyzer(nil), checks...)
	for i, a := range bound {
		if v, ok := a.(sourceRedirection); ok {
			v.declarations = facts
			bound[i] = v
		}
	}

	return out, bound
}

// OperationTasks is the single allocation model for shared preparation and
// independent rule projections. Each phase receives disjoint deterministic
// shares; nested contexts never accidentally reset or multiply a run's quota.
func OperationTasks(checks []Analyzer) int {
	tasks := len(checks) + pythonConsumerCount(checks) + LanguageConsumers(checks) + sourceConsumers(checks) + bundleConsumers(checks)
	if n := shellPatternConsumers(checks); n > 0 {
		tasks += n + 1
	}

	return tasks
}

func phaseQuota(ctx context.Context, checks []Analyzer, consumers int, operations uint64) context.Context {
	if operations == 0 {
		return ctx
	}

	return analysisbudget.WithLimit(ctx, operations/uint64(OperationTasks(checks))*uint64(consumers)) //nolint:gosec // G115: phase counts are nonnegative bounded analyzer counts.
}
