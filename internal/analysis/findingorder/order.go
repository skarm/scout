// Package findingorder defines the shared deterministic retention ordering.
package findingorder

import (
	"cmp"

	"github.com/skarm/scout/report"
)

func Before(a, b report.Finding) bool { return Compare(a, b) < 0 }
func Compare(a, b report.Finding) int {
	if c := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); c != 0 {
		return c
	}

	if c := cmp.Compare(a.Location.Path, b.Location.Path); c != 0 {
		return c
	}

	if c := cmp.Compare(a.Location.ByteStart, b.Location.ByteStart); c != 0 {
		return c
	}

	if c := cmp.Compare(a.Location.ByteEnd, b.Location.ByteEnd); c != 0 {
		return c
	}

	if c := cmp.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}

	return cmp.Compare(a.ID, b.ID)
}
