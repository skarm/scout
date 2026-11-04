package evaluation

import (
	"errors"
	"math"
)

// Requirements are operator-selected thresholds for static case-level metrics.
// Independence is declared provenance, not something a scanner can establish.
type Requirements struct {
	MinRecall          *float64 `json:"min_recall,omitempty"`
	MaxFalsePositive   *float64 `json:"max_false_positive_rate,omitempty"`
	MaxIncomplete      *int     `json:"max_incomplete,omitempty"`
	RequireIndependent bool     `json:"require_independent_holdout"`
}

type GateResult struct {
	Requirements Requirements `json:"requirements"`
	Passed       bool         `json:"passed"`
	Reasons      []string     `json:"reasons"`
}

func (r Requirements) Enabled() bool {
	return r.MinRecall != nil || r.MaxFalsePositive != nil || r.MaxIncomplete != nil || r.RequireIndependent
}

func (r Requirements) Validate() error {
	for _, value := range []*float64{r.MinRecall, r.MaxFalsePositive} {
		if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1) {
			return errors.New("metric thresholds must be finite values in 0..1")
		}
	}

	if r.MaxIncomplete != nil && *r.MaxIncomplete < 0 {
		return errors.New("maximum incomplete cases must be nonnegative")
	}

	return nil
}

// Assess never turns missing denominators, unfinished measurements or unreviewed
// sources into a passing gate. Findings are measured independently of LLM output.
func Assess(report Report, requirements Requirements) GateResult {
	result := GateResult{Requirements: requirements, Passed: true, Reasons: []string{}}

	fail := func(reason string) { result.Passed = false; result.Reasons = append(result.Reasons, reason) }
	if requirements.Validate() != nil {
		fail("invalid_requirements")
		return result
	}

	if !report.Completed || report.SelectedCases == 0 || len(report.Results) != report.SelectedCases {
		fail("measurement_incomplete")
	}

	if requirements.RequireIndependent && (report.CorpusKind != "independent_labelled_corpus" || report.SelectedSplit != "holdout") {
		fail("independent_holdout_required")
	}

	if requirements.RequireIndependent && (report.LabelReview == nil || !report.LabelReview.Independent || report.LabelReview.CorpusSHA256 != report.CorpusSHA256 || report.LabelReview.ReviewedCases < report.SelectedCases || len(report.LabelReview.Reviewers) == 0) {
		fail("trusted_independent_label_review_required")
	}

	if requirements.RequireIndependent && report.Overall.Ambiguous == report.SelectedCases {
		fail("labelled_holdout_required")
	}

	if report.CorpusKind == "external_unreviewed_corpus" {
		fail("independent_label_review_required")
	}

	if requirements.MinRecall != nil {
		if report.Overall.SignalRecall == nil {
			fail("recall_undefined")
		} else if *report.Overall.SignalRecall < *requirements.MinRecall {
			fail("recall_below_minimum")
		}
	}

	if requirements.MaxFalsePositive != nil {
		if report.Overall.FalsePositiveRate == nil {
			fail("false_positive_rate_undefined")
		} else if *report.Overall.FalsePositiveRate > *requirements.MaxFalsePositive {
			fail("false_positive_rate_above_maximum")
		}
	}

	if requirements.MaxIncomplete != nil && report.Overall.Incomplete > *requirements.MaxIncomplete {
		fail("incomplete_cases_above_maximum")
	}

	return result
}
