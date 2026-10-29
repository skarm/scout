package scenarios

import (
	"github.com/skarm/scout/internal/scantest"
)

func HasRule(r scantest.Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}

	return false
}
