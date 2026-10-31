package evaluation_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/review"
)

func TestLLMMetricsStaySeparateAndAccountForUsage(t *testing.T) {
	provider := &evaluationProvider{tokens: 100}
	opts := offlineOptions()
	settings := review.DefaultOptions()
	settings.Enabled, settings.AllowSourceUpload = true, true
	opts.Review = &scout.ReviewOptions{Provider: provider, Settings: settings}
	c := packageCorpus()
	c.Cases[0].Label = "signal"
	c.Cases[0].Files[0].Content = "MODEL_PROPOSAL_MARKER plain instructions"
	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, c), evaluation.Options{
		Reviewer: newScanner(t, opts), Price: &evaluation.TokenPrice{InputUSDPerMillion: 2, OutputUSDPerMillion: 4},
	})
	if err != nil || r.LLM == nil || !r.Completed || r.Overall.MissedPositive != 1 || r.Overall.DetectedPositive != 0 || r.LLM.Overall.DetectedPositive != 1 || r.LLM.Overall.CompleteNegativeBenign != 1 || r.LLM.Overall.Incomplete != 0 {
		t.Fatalf("channels mixed: %+v %v", r, err)
	}
	u := r.LLM.Usage
	if !u.Complete || u.CompletedRequests != int(provider.calls.Load()) || u.PlannedRequests != u.CompletedRequests || u.InputTokens != int64(u.CompletedRequests)*100 || u.OutputTokens != int64(u.CompletedRequests)*10 || r.LLM.EstimatedCostUSD == nil {
		t.Fatalf("usage lost: %+v", r.LLM)
	}
	wantCost := (float64(u.InputTokens)*2 + float64(u.OutputTokens)*4) / 1e6
	if math.Abs(*r.LLM.EstimatedCostUSD-wantCost) > 1e-12 || r.Results[0].Review.Identity.PromptSHA256 == "" || r.Results[0].Review.Identity.Provider.Model != "fixture" {
		t.Fatal("cost or review identity lost", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil || strings.Contains(string(encoded), "MODEL_PROPOSAL_MARKER") {
		t.Fatal("review report leaked source", err)
	}
}

func TestLLMFailuresAndUnknownTokensCannotBecomeSuccessfulNegatives(t *testing.T) {
	for _, fail := range []bool{false, true} {
		provider := &evaluationProvider{tokens: -1, fail: fail}
		opts := offlineOptions()
		settings := review.DefaultOptions()
		settings.Enabled, settings.AllowSourceUpload = true, true
		opts.Review = &scout.ReviewOptions{Provider: provider, Settings: settings}
		r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, packageCorpus()), evaluation.Options{
			Reviewer: newScanner(t, opts), Price: &evaluation.TokenPrice{InputUSDPerMillion: 2, OutputUSDPerMillion: 4},
		})
		if err != nil || r.LLM == nil || r.Overall.CompleteNegativeBenign != 2 || !r.Completed || r.LLM.Usage.Complete || r.LLM.EstimatedCostUSD != nil || r.LLM.Usage.UnknownRequests == 0 {
			t.Fatalf("unknown usage or failed model was accepted: %+v %v", r, err)
		}
		if fail && (r.LLM.Overall.UnresolvedBenign != 2 || r.LLM.Overall.CompleteNegativeBenign != 0 || r.LLM.Overall.FalsePositiveRate != nil) {
			t.Fatal("failed review became a successful negative", r.LLM)
		}
		encoded, err := json.Marshal(r)
		if err != nil || strings.Contains(string(encoded), "PRIVATE_PROVIDER_ERROR") {
			t.Fatal("provider error leaked", err)
		}
	}
}

func TestEvaluationRejectsWrongReviewerAndPrice(t *testing.T) {
	scanner := newScanner(t, offlineOptions())
	for _, opts := range []evaluation.Options{
		{Reviewer: scanner},
		{Price: &evaluation.TokenPrice{}},
		{Reviewer: scanner, Price: &evaluation.TokenPrice{InputUSDPerMillion: math.NaN()}},
		{Reviewer: scanner, Price: &evaluation.TokenPrice{OutputUSDPerMillion: -1}},
	} {
		if _, err := evaluation.MeasureWithOptions(t.Context(), scanner, encodeCorpus(t, packageCorpus()), opts); err == nil {
			t.Fatal("invalid review configuration accepted")
		}
	}
}

func TestCancellationRetainsFinalizedPartialMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	provider := &evaluationProvider{cancel: cancel}
	opts := offlineOptions()
	settings := review.DefaultOptions()
	settings.Enabled, settings.AllowSourceUpload = true, true
	opts.Review = &scout.ReviewOptions{Provider: provider, Settings: settings}
	r, err := evaluation.MeasureWithOptions(ctx, newScanner(t, offlineOptions()), encodeCorpus(t, packageCorpus()), evaluation.Options{Reviewer: newScanner(t, opts)})
	if !errors.Is(err, context.Canceled) || r.Completed || r.SelectedCases != 2 || len(r.Results) != 1 || r.Overall.CompleteNegativeBenign != 1 || r.Overall.FalsePositiveRate == nil || r.LLM == nil || r.LLM.Overall.UnresolvedBenign != 1 || r.LLM.Usage.Complete {
		t.Fatalf("partial accounting lost: %+v %v", r, err)
	}
}

func TestNoReviewableTextDoesNotCountAsLLMNegative(t *testing.T) {
	c := packageCorpus()
	c.Cases = c.Cases[:1]
	c.Cases[0].Files = []evaluation.File{{Path: "empty.txt", Content: ""}}
	provider := &evaluationProvider{tokens: 100}
	opts := offlineOptions()
	settings := review.DefaultOptions()
	settings.Enabled, settings.AllowSourceUpload = true, true
	opts.Review = &scout.ReviewOptions{Provider: provider, Settings: settings}
	r, err := evaluation.MeasureWithOptions(t.Context(), newScanner(t, offlineOptions()), encodeCorpus(t, c), evaluation.Options{Reviewer: newScanner(t, opts)})
	if err != nil || r.LLM == nil || provider.calls.Load() != 0 || r.LLM.Overall.CompleteNegativeBenign != 0 || r.LLM.Overall.UnresolvedBenign != 1 || r.LLM.Usage.Complete {
		t.Fatalf("absent LLM work counted as detection evidence: %+v %v", r, err)
	}
}

type evaluationProvider struct {
	calls  atomic.Int64
	tokens int64
	fail   bool
	cancel context.CancelFunc
}

func (p *evaluationProvider) Identity() review.Identity {
	return review.Identity{Provider: "fixture", Model: "fixture"}
}

func (p *evaluationProvider) Complete(ctx context.Context, data []byte) (review.Completion, error) {
	p.calls.Add(1)
	if p.cancel != nil {
		p.cancel()
	}
	if err := ctx.Err(); err != nil {
		return review.Completion{}, err
	}
	if p.fail {
		return review.Completion{}, errors.New("PRIVATE_PROVIDER_ERROR")
	}
	var req review.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return review.Completion{}, err
	}
	response := review.Response{SchemaVersion: review.ProtocolVersion, RequestID: req.RequestID, Proposals: []review.Proposal{}, Assessments: []review.Assessment{}}
	if req.Mode == "discovery" {
		for _, excerpt := range req.Excerpts {
			if strings.Contains(excerpt.Text, "MODEL_PROPOSAL_MARKER") {
				response.Proposals = append(response.Proposals, review.Proposal{Reason: "instruction_override", Severity: "high", Evidence: []review.Citation{{ExcerptID: excerpt.ID, SHA256: excerpt.SHA256}}})
				break
			}
		}
	}
	for _, finding := range req.Findings {
		response.Assessments = append(response.Assessments, review.Assessment{FindingID: finding.ID, Verdict: "confirmed", Reason: "supported_by_context", Evidence: finding.Evidence})
	}
	encoded, err := json.Marshal(response)
	return review.Completion{Output: encoded, InputTokens: p.tokens, OutputTokens: p.tokens / 10}, err
}
