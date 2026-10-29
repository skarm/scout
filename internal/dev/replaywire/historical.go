package replaywire

import (
	"errors"

	"github.com/skarm/scout/report"
)

// ValidateComparison allows the explicitly identified pre-state capture format
// for historical observation comparisons only. Acceptance and adjudication
// always call Record.Validate and require a run binding and an execution budget.
func ValidateComparison(r Record) error {
	if r.Version != "0.22.0-preview" {
		return r.Validate("")
	}

	if r.State != "" || r.RunDigest != "" || r.BudgetSeconds != 0 {
		return errors.New("mixed historical and current replay formats")
	}

	if !ValidDigest(r.ID) {
		return errors.New("invalid record ID")
	}

	if err := r.validateVocabulary(); err != nil {
		return err
	}

	if r.Coverage != report.Complete && r.Decision == report.Allow {
		return errors.New("incomplete historical replay input allowed")
	}

	return nil
}
