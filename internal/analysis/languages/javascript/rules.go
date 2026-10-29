// Package javascript implements bounded, non-executing JavaScript/TypeScript analysis over prepared syntax.
package javascript

import "github.com/skarm/scout/internal/analysis/check"

type (
	analyzer = check.Analyzer
	match    = check.Match
	trace    = check.Trace
	result   = check.Result
)

func Rules() []analyzer {
	out := make([]analyzer, 0, 6)
	for _, id := range []string{ruleJS001, ruleJS002, ruleJS003, ruleJS004, ruleJS005, ruleJS006} {
		out = append(out, scriptCheck{id: id})
	}

	return out
}
