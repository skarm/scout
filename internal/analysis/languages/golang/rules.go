// Package golang implements bounded, non-executing Go analysis over prepared syntax.
package golang

import "github.com/skarm/scout/internal/analysis/check"

type (
	analyzer = check.Analyzer
	match    = check.Match
	trace    = check.Trace
	result   = check.Result
)

func Rules() []analyzer {
	return []analyzer{goCheck{kind: goShell}, goCheck{kind: goSensitiveRead}, goCheck{kind: goDirectHTTP}, goFlow{}, goDatabaseCheck{}, goTLSCheck{}}
}
