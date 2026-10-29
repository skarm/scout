package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/python"
)

// BindPython evaluates prepared Python documents once, then binds immutable
// observations to all rule consumers before concurrent rule execution starts.
func BindPython(ctx context.Context, checks []Analyzer, docs []document.File, candidates int, operations uint64) []Analyzer {
	ids := pythonConsumers(checks)
	if len(ids) == 0 {
		return checks
	}

	ctx = phaseQuota(ctx, checks, len(ids), operations)
	facts := python.Prepare(ctx, docs, ids, candidates, 0)

	out := append([]Analyzer(nil), checks...)
	for i, a := range out {
		out[i] = python.WithFacts(a, facts)
		if v, ok := a.(pythonFactConsumer); ok {
			out[i] = v.withPython(facts)
		}
	}

	return out
}

func pythonConsumerCount(checks []Analyzer) int { return len(pythonConsumers(checks)) }

func pythonConsumers(checks []Analyzer) []string {
	var ids []string

	for _, a := range checks {
		if id, ok := python.RuleID(a); ok {
			ids = append(ids, id)
		}

		if v, ok := a.(pythonFactConsumer); ok {
			ids = append(ids, v.pythonID())
		}
	}

	return ids
}
