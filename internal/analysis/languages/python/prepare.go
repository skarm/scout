package python

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
)

func Prepare(ctx context.Context, docs []document.File, ids []string, candidates int, operations uint64) Facts {
	if operations > 0 {
		ctx = analysisbudget.WithLimit(ctx, operations)
	}

	facts := make(Facts, len(docs))

	remaining := make(map[string]int, len(ids))
	for _, id := range ids {
		remaining[id] = max(0, candidates)
	}

	for _, doc := range docs {
		collected := newPythonFactsWithin(remaining)
		collectPythonInto(ctx, doc, collected)

		for id, rule := range collected.outputs {
			remaining[id] -= rule.MatchCount()
		}

		facts[doc.Artifact().Metadata().Path] = collected
	}

	return facts
}

func collectPython(ctx context.Context, doc document.File, ids []string, candidates int) *pythonFacts {
	facts := newPythonFacts(ids, candidates)
	collectPythonInto(ctx, doc, facts)

	return facts
}

func collectPythonInto(ctx context.Context, doc document.File, facts *pythonFacts) {
	limited := false

	for _, unit := range doc.Units() {
		tree, ok := unit.Tree.(parse.PythonTree)
		if !ok || tree.Root == nil {
			continue
		}

		facts.beginUnit()
		walker := pyWalker{ctx: ctx, unit: unit, facts: facts}
		walker.block(tree.Root.List(frontend.Body), newPyState(), 0)

		limited = limited || walker.limited
		if walker.err != nil || walker.truncated {
			facts.finish(walker.err, walker.truncated)
			return
		}

		if facts.exhausted() {
			return
		}
	}

	facts.finish(ctx.Err(), limited)
}
