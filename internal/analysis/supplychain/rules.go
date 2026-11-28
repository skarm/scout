// Package supplychain checks declarations about module identity and package sources.
package supplychain

import "github.com/skarm/scout/internal/analysis/check"

// ModuleRules returns the base Go module checks.
func ModuleRules() []check.Analyzer {
	return []check.Analyzer{moduleCheck{id: ruleSC002}, moduleCheck{id: ruleSC003}}
}
