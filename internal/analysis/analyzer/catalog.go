package analyzer

import (
	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/analysis/languages/python"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/analysis/languages/sql"
	"github.com/skarm/scout/internal/analysis/rendertext"
	"github.com/skarm/scout/report"
)

// Selection retains the existing optional-check switches. Patterns includes
// supplemental structured checks as well as content patterns.
type Selection struct {
	Patterns, Python bool
}

// Catalog owns the static rule registrations used by execution and discovery.
type Catalog struct {
	base, supplemental, python []Analyzer
}

func NewCatalog(selection Selection) Catalog {
	catalog := Catalog{base: literalRules()}
	catalog.base = append(catalog.base, opaque{}, moduleCheck{id: ruleSC002}, moduleCheck{id: ruleSC003})
	catalog.base = append(catalog.base, rendertext.Rules()...)
	// Preserve the established order: Go database/TLS checks follow SQL.
	goRules := golang.Rules()
	catalog.base = append(catalog.base, goRules[:4]...)
	catalog.base = append(catalog.base, shell.Rules()...)
	catalog.base = append(catalog.base, agentRules()...)
	catalog.base = append(catalog.base, instructionRules()...)
	catalog.base = append(catalog.base, javascript.Rules()...)
	catalog.base = append(catalog.base, sql.Rules()...)
	catalog.base = append(catalog.base, goRules[4:]...)
	catalog.base = append(catalog.base, bundle.Rules()...)
	catalog.base = append(catalog.base, artifactIntegrityRules()...)

	if selection.Python {
		catalog.python = python.Rules()
	}

	if selection.Patterns {
		catalog.supplemental = combineRules(
			PatternRules(), MetadataRules(), PermissionRules(), ReferenceRules(),
			DependencyRules(), ActivationRules(), DeserializationPatternRules(), RegistryRules(),
		)
	}

	return catalog
}

// Analyzers returns a detached execution list. Python retains its position
// before supplemental checks so execution ordering remains compatible.
func (c Catalog) Analyzers() []Analyzer {
	return combineRules(c.base, c.python, c.supplemental)
}

// Rules returns detached descriptors in the established public catalog order.
// Discovery historically lists supplemental checks before Python checks.
func (c Catalog) Rules() []report.Rule {
	checks := combineRules(c.base, c.supplemental, c.python)

	rules := make([]report.Rule, 0, len(checks))
	for _, check := range checks {
		rules = append(rules, check.Rule())
	}

	return rules
}

func combineRules(groups ...[]Analyzer) []Analyzer {
	count := 0
	for _, group := range groups {
		count += len(group)
	}

	checks := make([]Analyzer, 0, count)
	for _, group := range groups {
		checks = append(checks, group...)
	}

	return checks
}
