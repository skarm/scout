package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
)

type shellPatternFacts map[string]*check.Facts

type shellPatternConsumer interface {
	Analyzer
	withShellPatterns(shellPatternFacts) Analyzer
	shellPatterns(context.Context, document.File, int) (Result, error)
}

func shellPatternConsumers(checks []Analyzer) int {
	n := 0

	for _, a := range checks {
		if _, ok := a.(shellPatternConsumer); ok {
			n++
		}
	}

	return n
}

// PrepareShellPatternsWithin owns candidate discovery, parser admission and
// frozen observations for all selected shell-backed pattern families. Projection
// never reparses a rejected source or spends a second copy of this run's quota.
func PrepareShellPatternsWithin(ctx context.Context, checks []Analyzer, docs []document.File, candidates int, operations uint64) ([]document.File, []Analyzer) {
	n := shellPatternConsumers(checks)
	if n == 0 {
		return docs, checks
	}

	ctx = phaseQuota(ctx, checks, n+1, operations)

	prepared := append([]document.File(nil), docs...)
	for i, d := range prepared {
		spans, limited := shell.CandidateSpans(ctx, d)
		prepared[i] = d.WithShellCandidates(ctx, spans, limited)
	}

	bound := append([]Analyzer(nil), checks...)
	for i, a := range bound {
		consumer, ok := a.(shellPatternConsumer)
		if !ok {
			continue
		}

		facts := shellPatternFacts{}

		remaining := candidates
		for _, d := range prepared {
			result, err := consumer.shellPatterns(ctx, d, remaining)

			observations := check.NewFacts(remaining)
			for _, m := range result.Matches {
				observations.Add(m)
			}

			observations.Finish(err, result.Truncated)
			remaining -= observations.MatchCount()
			facts[d.Artifact().Metadata().Path] = observations
		}

		bound[i] = consumer.withShellPatterns(facts)
	}

	return prepared, bound
}

func (a transmissionCheck) withShellPatterns(f shellPatternFacts) Analyzer {
	a.shellFacts = f
	return a
}

func (a removalCheck) withShellPatterns(f shellPatternFacts) Analyzer { a.shellFacts = f; return a }

func (a persistenceCheck) withShellPatterns(f shellPatternFacts) Analyzer { a.shellFacts = f; return a }

func (a downloadCheck) withShellPatterns(f shellPatternFacts) Analyzer { a.shellFacts = f; return a }
