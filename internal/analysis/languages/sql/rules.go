// Package sql implements bounded, non-executing SQL analysis over prepared syntax.
package sql

import "github.com/skarm/scout/internal/analysis/check"

type (
	analyzer = check.Analyzer
	match    = check.Match

	result = check.Result
)

func Rules() []analyzer {
	return []analyzer{sqlCheck{id: ruleSQL001}, sqlCheck{id: ruleSQL002}, sqlCheck{id: ruleSQL003}, sqlCheck{id: ruleSQL004}}
}
