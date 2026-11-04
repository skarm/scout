package evaluation_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/internal/dev/evaluation"
)

func TestReviewedLabelsBindTheMeasurementAndKeepSourceCorpusUnchanged(t *testing.T) {
	data, document := labelReviewFixture(t)
	raw := encodeLabelReview(t, document)
	review, err := evaluation.ValidateLabelReview(data, raw, []string{"fixture-reviewer"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "holdout", LabelReview: review})
	if err != nil || !r.Completed || r.CorpusKind != "independent_labelled_corpus" || r.Overall.CompleteNegativeBenign != 1 || r.LabelReview == nil || r.LabelReview.InputKind != "external_unreviewed_corpus" || r.LabelReview.CorpusSHA256 != r.CorpusSHA256 || r.LabelReview.ReviewedCases != 2 || !reflect.DeepEqual(r.LabelReview.Reviewers, []string{"fixture-reviewer"}) {
		t.Fatalf("review provenance or applied labels lost: report=%+v err=%v", r, err)
	}
	zero := 0.0
	if result := evaluation.Assess(r, evaluation.Requirements{RequireIndependent: true, MaxFalsePositive: &zero}); !result.Passed {
		t.Fatal(result.Reasons)
	}
	encoded, err := json.Marshal(r)
	if err != nil || bytes.Contains(encoded, []byte("PRIVATE_RATIONALE")) || bytes.Contains(encoded, []byte("review-evidence.invalid")) || bytes.Contains(encoded, []byte("sample-a ordinary documentation")) {
		t.Fatal("raw review or case content leaked into the measurement report", err)
	}
	original, err := evaluation.Parse(data)
	if err != nil || original.Kind != "external_unreviewed_corpus" || original.Cases[0].Label != "ambiguous" {
		t.Fatal("applying review labels mutated the raw corpus")
	}
	r.LabelReview.Reviewers[0] = "mutated-report"
	second, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "holdout", LabelReview: review})
	if err != nil || !reflect.DeepEqual(second.LabelReview.Reviewers, []string{"fixture-reviewer"}) {
		t.Fatal("report mutation changed validated reviewer authority", err)
	}
	changed := append(slices.Clone(data), '\n')
	if _, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), changed, evaluation.Options{LabelReview: review}); err == nil {
		t.Fatal("validated review was reused against different corpus bytes")
	}
}

func TestNonIndependentReviewCannotPromoteExternalData(t *testing.T) {
	data, document := labelReviewFixture(t)
	document.Independent = false
	review, err := evaluation.ValidateLabelReview(data, encodeLabelReview(t, document), []string{"fixture-reviewer"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), data, evaluation.Options{Split: "holdout", LabelReview: review})
	if err != nil || r.CorpusKind != "external_labelled_corpus" || r.LabelReview == nil || r.LabelReview.Independent {
		t.Fatalf("nonindependent labels were promoted: %+v %v", r, err)
	}
	if gate := evaluation.Assess(r, evaluation.Requirements{RequireIndependent: true}); gate.Passed {
		t.Fatal("nonindependent labels satisfied the independent gate")
	}
}

func TestLabelReviewRejectsIncompleteUntrustedAndStaleDecisions(t *testing.T) {
	data, document := labelReviewFixture(t)
	for name, change := range map[string]func(*evaluation.LabelReviewDocument){
		"pending":        func(d *evaluation.LabelReviewDocument) { d.Reviews[0].Label = "pending" },
		"unknown-label":  func(d *evaluation.LabelReviewDocument) { d.Reviews[0].Label = "safe" },
		"unknown-case":   func(d *evaluation.LabelReviewDocument) { d.Reviews[0].CaseID = "unknown" },
		"duplicate-case": func(d *evaluation.LabelReviewDocument) { d.Reviews[1].CaseID = d.Reviews[0].CaseID },
		"missing-case":   func(d *evaluation.LabelReviewDocument) { d.Reviews = d.Reviews[:1] },
		"untrusted":      func(d *evaluation.LabelReviewDocument) { d.Reviews[0].ReviewerID = "other-reviewer" },
		"no-rationale":   func(d *evaluation.LabelReviewDocument) { d.Reviews[0].Rationale = "" },
		"future-time":    func(d *evaluation.LabelReviewDocument) { d.Reviews[0].ReviewedAt = "2999-01-01T00:00:00Z" },
		"missing-time":   func(d *evaluation.LabelReviewDocument) { d.Reviews[0].ReviewedAt = "" },
		"no-evidence":    func(d *evaluation.LabelReviewDocument) { d.Reviews[0].Evidence = []string{} },
		"evidence-auth": func(d *evaluation.LabelReviewDocument) {
			d.Reviews[0].Evidence = []string{"https://name:password@example.invalid"}
		},
		"evidence-query": func(d *evaluation.LabelReviewDocument) {
			d.Reviews[0].Evidence = []string{"https://example.invalid/?token=private"}
		},
		"stale-corpus": func(d *evaluation.LabelReviewDocument) { d.CorpusSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var changed evaluation.LabelReviewDocument
			if err := json.Unmarshal(encodeLabelReview(t, document), &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if _, err := evaluation.ValidateLabelReview(data, encodeLabelReview(t, changed), []string{"fixture-reviewer"}, time.Now()); err == nil {
				t.Fatal("invalid label review accepted")
			}
		})
	}
	for _, trusted := range [][]string{nil, {"fixture-reviewer", "fixture-reviewer"}, {"invalid reviewer"}} {
		if _, err := evaluation.ValidateLabelReview(data, encodeLabelReview(t, document), trusted, time.Now()); err == nil {
			t.Fatal("reviewer authority was implicit or ambiguous")
		}
	}
}

func TestLabelReviewTemplateCannotPassAsACompletedReview(t *testing.T) {
	data, document := labelReviewFixture(t)
	template, err := evaluation.LabelReviewTemplate(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluation.ValidateLabelReview(data, template, []string{"fixture-reviewer"}, time.Now()); err == nil {
		t.Fatal("pending template became a completed review")
	}
	raw := encodeLabelReview(t, document)
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`"independent":true`), []byte(`"independent":null`), 1),
		append(slices.Clone(raw), []byte(`{}`)...),
	} {
		if _, err := evaluation.ValidateLabelReview(data, bad, []string{"fixture-reviewer"}, time.Now()); err == nil {
			t.Fatal("ambiguous label review JSON accepted")
		}
	}
}

func TestAuthoredCorpusCannotBePromotedToIndependentThroughReview(t *testing.T) {
	data := encodeCorpus(t, packageCorpus())
	template, err := evaluation.LabelReviewTemplate(data)
	if err != nil {
		t.Fatal(err)
	}
	var document evaluation.LabelReviewDocument
	if err := json.Unmarshal(template, &document); err != nil {
		t.Fatal(err)
	}
	completeLabelReview(&document)
	if _, err := evaluation.ValidateLabelReview(data, encodeLabelReview(t, document), []string{"fixture-reviewer"}, time.Now()); err == nil {
		t.Fatal("an authored regression became an independent holdout")
	}
}

func labelReviewFixture(t *testing.T) ([]byte, evaluation.LabelReviewDocument) {
	t.Helper()
	corpus := packageCorpus()
	corpus.Kind = "external_unreviewed_corpus"
	for i := range corpus.Cases {
		corpus.Cases[i].Label = "ambiguous"
	}
	data := encodeCorpus(t, corpus)
	template, err := evaluation.LabelReviewTemplate(data)
	if err != nil {
		t.Fatal(err)
	}
	var document evaluation.LabelReviewDocument
	if err := json.Unmarshal(template, &document); err != nil {
		t.Fatal(err)
	}
	completeLabelReview(&document)
	return data, document
}

func completeLabelReview(document *evaluation.LabelReviewDocument) {
	document.Independent = true
	for i := range document.Reviews {
		document.Reviews[i].Label = "benign"
		document.Reviews[i].ReviewerID = "fixture-reviewer"
		document.Reviews[i].ReviewedAt = "2026-01-01T00:00:00Z"
		document.Reviews[i].Rationale = "PRIVATE_RATIONALE synthetic fixture; not an actual independent classification."
		document.Reviews[i].Evidence = []string{"https://review-evidence.invalid/fixture"}
	}
}

func encodeLabelReview(t *testing.T, document evaluation.LabelReviewDocument) []byte {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
