package evaluation_test

import (
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/dev/evaluation"
)

func TestMetricGatesRejectUndefinedAndUnreviewedMeasurements(t *testing.T) {
	recall, fpr, zero := 0.9, 0.05, 0
	requirements := evaluation.Requirements{MinRecall: &recall, MaxFalsePositive: &fpr, MaxIncomplete: &zero, RequireIndependent: true}
	report := evaluation.Report{Completed: true, SelectedCases: 2, SelectedSplit: "holdout", CorpusKind: "independent_labelled_corpus", Results: make([]evaluation.Result, 2), Overall: evaluation.Metrics{SignalRecall: &recall, FalsePositiveRate: &fpr}}
	report.CorpusSHA256 = strings.Repeat("a", 64)
	report.LabelReview = &evaluation.LabelReviewSummary{CorpusSHA256: report.CorpusSHA256, Independent: true, ReviewedCases: 2, Reviewers: []string{"fixture-reviewer"}}
	if result := evaluation.Assess(report, requirements); !result.Passed {
		t.Fatal(result.Reasons)
	}
	for _, tc := range []struct {
		change func(*evaluation.Report)
		reason string
	}{
		{func(r *evaluation.Report) { r.Completed = false }, "measurement_incomplete"},
		{func(r *evaluation.Report) { r.SelectedSplit = "tune" }, "independent_holdout_required"},
		{func(r *evaluation.Report) { r.CorpusKind = "external_unreviewed_corpus" }, "independent_label_review_required"},
		{func(r *evaluation.Report) { r.LabelReview = nil }, "trusted_independent_label_review_required"},
		{func(r *evaluation.Report) { r.Overall.Ambiguous = r.SelectedCases }, "labelled_holdout_required"},
		{func(r *evaluation.Report) { r.Overall.SignalRecall = nil }, "recall_undefined"},
		{func(r *evaluation.Report) { r.Overall.FalsePositiveRate = nil }, "false_positive_rate_undefined"},
		{func(r *evaluation.Report) { r.Overall.Incomplete = 1 }, "incomplete_cases_above_maximum"},
	} {
		changed := report
		tc.change(&changed)
		result := evaluation.Assess(changed, requirements)
		if result.Passed || !slices.Contains(result.Reasons, tc.reason) {
			t.Fatalf("missing %s: %+v", tc.reason, result)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), -0.1, 1.1} {
		if err := (evaluation.Requirements{MinRecall: &bad}).Validate(); err == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
}
