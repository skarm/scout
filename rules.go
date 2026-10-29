package scout

import (
	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/engine"
	"github.com/skarm/scout/knowledge"

	"github.com/skarm/scout/report"
)

// Rule describes a trusted scanner check, including its coverage limitations.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type Rule = report.Rule

// Rules returns a detached catalog without capturing input or contacting services.
// With all=true it also includes opt-in checks, even when their backend is not
// linked. InspectionPlan describes availability and selection for a given scan.
func Rules(all bool) []Rule {
	checks := analyzer.Builtins()
	if all {
		checks = append(checks, analyzer.SkillspectorPatterns()...)
		checks = append(checks, analyzer.PluginSecurityRules()...)
		checks = append(checks, analyzer.PythonRules()...)
	}

	rules := make([]Rule, 0, len(checks))
	for _, check := range checks {
		rules = append(rules, knowledge.WithGuidance(check.Rule()))
	}

	if all {
		rules = append(rules, engine.SignatureRules()...)
		rules = append(rules, engine.VulnerabilityRule())
	}

	return rules
}
