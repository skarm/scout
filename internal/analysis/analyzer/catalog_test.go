package analyzer_test

import (
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/report"
)

func TestCatalogPreservesLanguageRegistrationAndOptionalSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection analyzer.Selection
		count     int
	}{
		{name: "base", count: 62},
		{name: "python", selection: analyzer.Selection{Python: true}, count: 78},
		{name: "patterns", selection: analyzer.Selection{Patterns: true}, count: 138},
		{name: "all", selection: analyzer.Selection{Patterns: true, Python: true}, count: 154},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := analyzer.NewCatalog(tc.selection)
			checks := catalog.Analyzers()
			if len(checks) != tc.count {
				t.Fatalf("selected %d checks, want %d", len(checks), tc.count)
			}
			selected := make(map[string]report.Rule, len(checks))
			for _, check := range checks {
				rule := check.Rule()
				if _, exists := selected[rule.ID]; exists {
					t.Fatalf("duplicate rule %s", rule.ID)
				}
				selected[rule.ID] = rule
			}
			for _, id := range []string{"PI001", "GO001", "GO005", "GO006", "JS001", "SH001", "SQL001"} {
				if _, exists := selected[id]; !exists {
					t.Errorf("base rule missing: %s", id)
				}
			}
			for _, id := range []string{"NV-P1", "NV-TP1", "NV-LP1", "NV-SC9", "NV-SC5", "NV-SC10", "NV-TR1M", "NV-DS1", "MCP-PACKAGE-VERSION"} {
				if _, exists := selected[id]; exists != tc.selection.Patterns {
					t.Errorf("supplemental selection changed: %s", id)
				}
			}
			for _, id := range []string{"PY-AST1", "PY-TT6"} {
				if _, exists := selected[id]; exists != tc.selection.Python {
					t.Errorf("Python selection changed: %s", id)
				}
			}
			descriptors := catalog.Rules()
			if len(descriptors) != len(checks) {
				t.Fatal("discovery and execution inventories differ")
			}
			for _, rule := range descriptors {
				if !reflect.DeepEqual(rule, selected[rule.ID]) {
					t.Errorf("discovery and execution descriptors differ: %s", rule.ID)
				}
			}
		})
	}
}

func TestCatalogRetainsIndependentOrderingAndDetachedLists(t *testing.T) {
	catalog := analyzer.NewCatalog(analyzer.Selection{Patterns: true, Python: true})
	checks, descriptors := catalog.Analyzers(), catalog.Rules()
	if checks[62].Rule().ID != "PY-AST1" || checks[78].Rule().ID != "NV-P1" || descriptors[62].ID != "NV-P1" || descriptors[138].ID != "PY-AST1" {
		t.Fatal("execution or public catalog ordering changed")
	}
	checks[0] = nil
	descriptors[0].ID = "changed"
	if catalog.Analyzers()[0].Rule().ID != "PI001" || catalog.Rules()[0].ID != "PI001" {
		t.Fatal("caller mutation changed the registered catalog")
	}
}
