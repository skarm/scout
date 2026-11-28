package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/analysis/supplychain"
)

func generatedShellConsumers(checks []Analyzer) int {
	for _, a := range checks {
		_, pattern := a.(shellPatternConsumer)
		if shell.IsCheck(a) || pattern {
			return 1
		}
	}

	return 0
}

// PrepareGeneratedShellWithin admits mapped shell scripts under the same parser
// budget as their enclosing documents and before the shell facts are collected.
func PrepareGeneratedShellWithin(ctx context.Context, checks []Analyzer, docs []document.File, operations uint64) []document.File {
	if generatedShellConsumers(checks) == 0 {
		return docs
	}

	ctx = phaseQuota(ctx, checks, 1, operations)

	out := append([]document.File(nil), docs...)
	remainingBytes := document.MaxScanBytes

	for i, doc := range out {
		out[i] = prepareGeneratedShell(ctx, doc, &remainingBytes)
	}

	return out
}

func prepareGeneratedShell(ctx context.Context, doc document.File, remainingBytes *int) document.File {
	const maxGenerations = 4

	for start, generation := 0, 0; ; generation++ {
		units := doc.Units()
		if start == len(units) {
			return doc
		}

		remaining := document.MaxRegions - len(units)
		if generation == maxGenerations {
			remaining = 0
		}

		recovery := shell.RecoverGeneratedShellIn(ctx, units[start:], remaining, *remainingBytes)
		for _, view := range recovery.Views {
			*remainingBytes -= len(view.Text())
		}

		doc = doc.WithGeneratedShell(ctx, recovery.Views, recovery.Gaps, recovery.Issues...)
		doc = doc.WithGeneratedShellExecutions(recovery.Executions, recovery.ExecutionLimited)

		if len(recovery.Views) == 0 {
			return doc
		}

		start = len(units)
	}
}

// PrepareDerivedWithin assigns the source declaration prepass its share of the run quota.
func PrepareDerivedWithin(ctx context.Context, checks []Analyzer, docs []document.File, candidates int, operations uint64) ([]document.File, []Analyzer) {
	consumers := supplychain.SourceConsumers(checks)
	if consumers == 0 {
		return docs, checks
	}

	return supplychain.PrepareSources(phaseQuota(ctx, checks, consumers, operations), checks, docs, candidates)
}

// OperationTasks is the single allocation model for shared preparation and
// independent rule projections. Each phase receives disjoint deterministic
// shares; nested contexts never accidentally reset or multiply a run's quota.
func OperationTasks(checks []Analyzer) int {
	tasks := len(checks) + pythonConsumerCount(checks) + LanguageConsumers(checks) + supplychain.SourceConsumers(checks) + bundleConsumers(checks) + generatedShellConsumers(checks)
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
