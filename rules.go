package scout

import (
	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/engine"
	"github.com/skarm/scout/knowledge"

	"github.com/skarm/scout/report"
)

// Rule describes a trusted scanner check, including its coverage limitations.
type Rule = report.Rule

// Rules returns a detached catalog without capturing input or contacting services.
// With all=true it also includes opt-in checks, even when their backend is not
// linked. InspectionPlan describes availability and selection for a given scan.
func Rules(all bool) []Rule {
	catalog := analyzer.NewCatalog(analyzer.Selection{Patterns: all, Python: all})

	rules := catalog.Rules()
	for i := range rules {
		rules[i] = knowledge.WithGuidance(rules[i])
	}

	if all {
		rules = append(rules, engine.SignatureRules()...)
		rules = append(rules, engine.VulnerabilityRule())
	}

	return rules
}
