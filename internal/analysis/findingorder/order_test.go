package findingorder_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/findingorder"

	"github.com/skarm/scout/report"
)

func TestRetentionOrdering(t *testing.T) {
	base := report.Finding{
		ID:       "b",
		RuleID:   "B",
		Severity: report.Medium,
		Location: report.Location{
			Path:      "b",
			ByteStart: 2,
			ByteEnd:   4,
		},
	}
	for name, change := range map[string]func(*report.Finding){
		"severity": func(f *report.Finding) { f.Severity = report.High },
		"path":     func(f *report.Finding) { f.Location.Path = "a" },
		"start":    func(f *report.Finding) { f.Location.ByteStart = 1 },
		"end":      func(f *report.Finding) { f.Location.ByteEnd = 3 },
		"rule":     func(f *report.Finding) { f.RuleID = "A" },
		"id":       func(f *report.Finding) { f.ID = "a" },
	} {
		t.Run(name, func(t *testing.T) {
			first := base
			change(&first)
			if !findingorder.Before(first, base) || findingorder.Before(base, first) || findingorder.Compare(base, base) != 0 {
				t.Fatal("retention ordering inconsistent")
			}
		})
	}
}
