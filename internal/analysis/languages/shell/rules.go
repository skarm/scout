// Package shell implements bounded, non-executing Shell analysis over prepared syntax.
package shell

import "github.com/skarm/scout/internal/analysis/check"

type (
	analyzer = check.Analyzer
	match    = check.Match
	trace    = check.Trace
	result   = check.Result
)

func Rules() []analyzer {
	return []analyzer{shellCheck{kind: ruleSH001}, shellCheck{kind: ruleSH002}, shellCheck{kind: ruleSH003}, shellCheck{kind: ruleSH004}}
}
