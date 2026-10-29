// Package python implements bounded, non-executing Python analysis over the
// Tree-sitter frontend's typed Go nodes. It owns its interpreter and facts.
package python

import (
	"context"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
)

type (
	match    = check.Match
	trace    = check.Trace
	result   = check.Result
	analyzer = check.Analyzer
)

// Facts is a prepared immutable per-document observation set.
type Facts map[string]*pythonFacts

func RuleID(a check.Analyzer) (string, bool) { v, ok := a.(pythonCheck); return v.id, ok }
func WithFacts(a check.Analyzer, facts Facts) check.Analyzer {
	if v, ok := a.(pythonCheck); ok {
		v.facts = facts
		return v
	}

	return a
}

func Find(ctx context.Context, d document.File, id string, budget int, facts Facts) (result, error) {
	return (pythonCheck{id: id, facts: facts}).Find(ctx, d, budget)
}
