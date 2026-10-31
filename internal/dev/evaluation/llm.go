package evaluation

import (
	"errors"
	"math"
	"slices"

	"github.com/skarm/scout"
	"github.com/skarm/scout/report"
)

type Options struct {
	Split    string
	Reviewer *scout.Scanner
	Price    *TokenPrice
}

// TokenPrice is an operator assumption, not a fetched provider tariff.
type TokenPrice struct {
	InputUSDPerMillion  float64 `json:"input_usd_per_million"`
	OutputUSDPerMillion float64 `json:"output_usd_per_million"`
}

type Usage struct {
	PlannedRequests   int   `json:"planned_requests"`
	CompletedRequests int   `json:"completed_requests"`
	RequestBytes      int   `json:"request_bytes"`
	InputTokens       int64 `json:"known_input_tokens"`
	OutputTokens      int64 `json:"known_output_tokens"`
	UnknownRequests   int   `json:"unknown_usage_requests"`
	Complete          bool  `json:"complete"`
}

type ReviewIdentity struct {
	Provider             report.ProviderIdentity `json:"provider"`
	ProtocolVersion      string                  `json:"protocol_version"`
	PromptVersion        string                  `json:"prompt_version"`
	PromptSHA256         string                  `json:"prompt_sha256"`
	ResponseSchemaSHA256 string                  `json:"response_schema_sha256"`
	Settings             report.SemanticSettings `json:"settings"`
}

type ReviewResult struct {
	Reasons      []string              `json:"proposal_reasons"`
	Decision     string                `json:"decision"`
	Completeness string                `json:"completeness"`
	ScanFailed   bool                  `json:"scan_failed"`
	DurationNS   int64                 `json:"duration_ns"`
	Identity     ReviewIdentity        `json:"identity"`
	Engine       report.EngineIdentity `json:"engine"`
	Usage        Usage                 `json:"usage"`
}

type LLMReport struct {
	Inspection       report.InspectionPlan `json:"inspection"`
	Overall          Metrics               `json:"overall"`
	Categories       map[string]Metrics    `json:"categories"`
	Splits           map[string]Metrics    `json:"splits"`
	P50NS            int64                 `json:"p50_scan_ns"`
	P95NS            int64                 `json:"p95_scan_ns"`
	Usage            Usage                 `json:"usage"`
	Price            *TokenPrice           `json:"price_assumption,omitempty"`
	EstimatedCostUSD *float64              `json:"estimated_cost_usd"`
	durations        []int64
}

func (o Options) validate(c Corpus) error {
	if o.Split != "" && (!validSplit(o.Split) || !slices.ContainsFunc(c.Cases, func(tc Case) bool { return tc.Split == o.Split })) {
		return errors.New("selected split is invalid or empty")
	}

	if o.Price != nil {
		if o.Reviewer == nil {
			return errors.New("token prices require a reviewer")
		}

		for _, price := range []float64{o.Price.InputUSDPerMillion, o.Price.OutputUSDPerMillion} {
			if math.IsNaN(price) || math.IsInf(price, 0) || price < 0 || price > 1e9 {
				return errors.New("invalid token price assumption")
			}
		}
	}

	if o.Reviewer == nil {
		return nil
	}

	plan := o.Reviewer.InspectionPlan()
	if plan.Egress.Download || plan.Egress.VulnerabilityNetwork || !plan.Egress.SourceUpload {
		return errors.New("evaluation reviewer requires only explicit source upload")
	}

	semantic := false

	for _, check := range plan.Checks {
		if check.Selected && check.ID == "vulnerabilities" {
			return errors.New("evaluation cannot mix vulnerability services with LLM metrics")
		}

		semantic = semantic || check.Selected && check.ID == "semantic"
	}

	if !semantic {
		return errors.New("evaluation reviewer requires selected semantic checks")
	}

	return nil
}

func newLLMReport(o Options) *LLMReport {
	r := &LLMReport{
		Inspection: o.Reviewer.InspectionPlan(),
		Categories: map[string]Metrics{},
		Splits:     map[string]Metrics{},
		Usage:      Usage{Complete: true},
	}
	if o.Price != nil {
		price := *o.Price
		r.Price = &price
	}

	return r
}

func reviewResult(result Result, semantic report.SemanticReport) *ReviewResult {
	r := &ReviewResult{
		Reasons:      []string{},
		Decision:     result.Decision,
		Completeness: result.Completeness,
		ScanFailed:   result.ScanFailed || !semantic.Enabled || semantic.Completeness != report.Complete || len(semantic.Tasks) == 0,
		DurationNS:   result.DurationNS,
		Engine:       result.Engine,
		Identity: ReviewIdentity{
			Provider: semantic.Provider, ProtocolVersion: semantic.ProtocolVersion,
			PromptVersion: semantic.PromptVersion, PromptSHA256: semantic.PromptSHA256,
			ResponseSchemaSHA256: semantic.ResponseSchemaSHA256, Settings: semantic.Options,
		},
		Usage: Usage{
			PlannedRequests: len(semantic.Tasks), CompletedRequests: semantic.CompletedRequests,
			RequestBytes: semantic.RequestBytes, Complete: !result.ScanFailed && semantic.Enabled && semantic.Completeness == report.Complete && len(semantic.Tasks) > 0,
		},
	}
	for _, proposal := range semantic.Proposals {
		if !slices.Contains(r.Reasons, proposal.Reason) {
			r.Reasons = append(r.Reasons, proposal.Reason)
		}
	}

	slices.Sort(r.Reasons)

	for _, outcome := range semantic.Outcomes {
		if outcome.Status != report.OutcomeCompleted || outcome.InputTokens < 0 || outcome.OutputTokens < 0 {
			r.Usage.UnknownRequests++
			r.Usage.Complete = false
		}

		addTokens(&r.Usage, outcome.InputTokens, outcome.OutputTokens)
	}

	if len(semantic.Outcomes) != len(semantic.Tasks) {
		r.Usage.Complete = false
	}

	return r
}

func (r *LLMReport) add(result Result) {
	review := result.Review
	measured := Result{Label: result.Label, Rules: review.Reasons, Completeness: review.Completeness, ScanFailed: review.ScanFailed}
	add(&r.Overall, measured)
	m := r.Categories[result.Category]
	add(&m, measured)
	r.Categories[result.Category] = m
	m = r.Splits[result.Split]
	add(&m, measured)
	r.Splits[result.Split] = m
	r.durations = append(r.durations, review.DurationNS)
	r.Usage.PlannedRequests += review.Usage.PlannedRequests
	r.Usage.CompletedRequests += review.Usage.CompletedRequests
	r.Usage.RequestBytes += review.Usage.RequestBytes
	r.Usage.UnknownRequests += review.Usage.UnknownRequests
	r.Usage.Complete = r.Usage.Complete && review.Usage.Complete
	addTokens(&r.Usage, review.Usage.InputTokens, review.Usage.OutputTokens)
}

func addTokens(usage *Usage, input, output int64) {
	if input >= 0 && input <= math.MaxInt64-usage.InputTokens {
		usage.InputTokens += input
	} else {
		usage.Complete = false
	}

	if output >= 0 && output <= math.MaxInt64-usage.OutputTokens {
		usage.OutputTokens += output
	} else {
		usage.Complete = false
	}
}

func (r *LLMReport) finish() {
	finish(&r.Overall)
	finishGroups(r.Categories)
	finishGroups(r.Splits)

	if len(r.durations) == 0 {
		r.Usage.Complete = false
		return
	}

	slices.Sort(r.durations)
	r.P50NS = r.durations[(len(r.durations)-1)/2]

	r.P95NS = r.durations[(95*len(r.durations)+99)/100-1]
	if r.Price != nil && r.Usage.Complete {
		cost := (float64(r.Usage.InputTokens)*r.Price.InputUSDPerMillion + float64(r.Usage.OutputTokens)*r.Price.OutputUSDPerMillion) / 1e6
		r.EstimatedCostUSD = &cost
	}
}
