package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

// Quota limits admission inside an already valid provider configuration. Zero
// is a real exhausted quota, not an invalid transport or an unlimited budget.
type Quota struct{ Requests, InputBytes int }

// ProviderIdentity catches a broken trusted adapter without exposing panic text.
func ProviderIdentity(p review.Provider) (id review.Identity, err error) {
	if p == nil {
		return id, errors.New("semantic provider is required")
	}

	defer func() {
		if recover() != nil {
			err = errors.New("semantic provider identity failed")
		}
	}()

	id = p.Identity()

	return id, id.Validate()
}

func Run(ctx context.Context, files []artifact.File, graph report.ComponentGraph, findings []report.Finding, snapshot string, o review.Options, provider review.Provider) report.SemanticReport {
	return runWithExtraction(ctx, files, graph, findings, snapshot, o, provider, report.ExtractionReport{})
}

func runWithExtraction(ctx context.Context, files []artifact.File, graph report.ComponentGraph, findings []report.Finding, snapshot string, o review.Options, provider review.Provider, extraction report.ExtractionReport) report.SemanticReport {
	return RunWithin(ctx, files, graph, findings, snapshot, o, provider, extraction, nil)
}

func RunWithin(ctx context.Context, files []artifact.File, graph report.ComponentGraph, findings []report.Finding, snapshot string, o review.Options, provider review.Provider, extraction report.ExtractionReport, quota *Quota) report.SemanticReport {
	schema, _ := json.Marshal(review.ResponseSchema())

	r := report.SemanticReport{
		Enabled:              o.Enabled,
		Scope:                "bounded text discovery; declared-plugin/standalone-document intent context; static-finding assessment and second-stage semantic-proposal assessment (not runtime verification)",
		ProtocolVersion:      review.ProtocolVersion,
		PromptVersion:        review.PromptVersion,
		InstructionPack:      knowledge.Inventory(),
		PromptSHA256:         knowledge.Inventory().SHA256,
		ResponseSchemaSHA256: artifact.Hash(schema),
		Options:              report.SemanticSettings(o),
		Tasks:                []report.SemanticTask{},
		Outcomes:             []report.SemanticOutcome{},
		Gaps:                 []report.SemanticGap{},
		Proposals:            []report.SemanticProposal{},
		Assessments:          []report.SemanticAssessment{},
		ProposalAssessments:  []report.SemanticProposalAssessment{},
	}
	if !o.Enabled {
		r.Scope = "disabled: no source upload or semantic validation requested"
		return r
	}

	r.Completeness = report.Complete
	if ctx == nil || o.Validate() != nil {
		r.Completeness = report.Failed
		r.Gaps = append(r.Gaps, report.SemanticGap{Code: "invalid_semantic_configuration"})

		return r
	}

	id, err := ProviderIdentity(provider)
	if err != nil {
		r.Completeness = report.Failed
		r.Gaps = append(r.Gaps, report.SemanticGap{Code: "provider_unavailable"})

		return r
	}

	r.Provider = report.ProviderIdentity(id)

	if quota != nil {
		o.MaxRequests = min(o.MaxRequests, quota.Requests)
		o.MaxInputBytes = min(o.MaxInputBytes, quota.InputBytes)
		r.Options.MaxRequests = o.MaxRequests
		r.Options.MaxInputBytes = o.MaxInputBytes
	}

	p := build(ctx, files, graph, findings, snapshot, o, extraction)
	r.Gaps = p.gaps

	r.OmittedGaps = p.omittedGaps
	for _, w := range p.works {
		r.Tasks = append(r.Tasks, w.metadata)
	}

	r.InitialTaskCount, r.InitialGapCount, r.InitialOmittedGaps = len(r.Tasks), len(r.Gaps), r.OmittedGaps
	canonical, _ := json.Marshal(struct {
		Snapshot       string
		Host           string
		Provider       review.Identity
		Prompt, Schema string
		Options        review.Options
		Tasks          []report.SemanticTask
		Gaps           []report.SemanticGap
	}{
		Snapshot: snapshot,
		Host:     graph.RequestedHost,
		Provider: id,
		Prompt:   r.PromptSHA256,
		Schema:   r.ResponseSchemaSHA256,
		Options:  o,
		Tasks:    r.Tasks,
		Gaps:     r.Gaps,
	})
	binding, _ := json.Marshal(struct {
		Plan        json.RawMessage
		OmittedGaps int
	}{Plan: canonical, OmittedGaps: p.omittedGaps})
	r.PlanSHA256 = artifact.Hash(binding)
	// The full list and input hashes now exist before the first provider call.
	// Single-flight execution within a scan bounds spend and preserves task order.
	abortReason := ""
	execute := func(works []work) {
		for _, w := range works {
			outcome, nextAbort := executeWork(ctx, provider, w, o, &r, abortReason)
			abortReason = nextAbort

			r.Outcomes = append(r.Outcomes, outcome)
		}
	}
	execute(p.works)
	// Verification tasks bind accepted proposals to the initial plan.
	verification, verificationHash := p.planVerification(r.Proposals, r.PlanSHA256)

	r.VerificationPlanSHA256 = verificationHash
	for _, w := range verification {
		r.Tasks = append(r.Tasks, w.metadata)
	}

	r.Gaps, r.OmittedGaps = p.gaps, p.omittedGaps

	execute(verification)
	finishSemanticReport(&r)

	return r
}

func executeWork(ctx context.Context, provider review.Provider, w work, o review.Options, r *report.SemanticReport, abortReason string) (report.SemanticOutcome, string) {
	outcome := report.SemanticOutcome{
		TaskID:       w.metadata.ID,
		Status:       report.OutcomeNotRun,
		Reason:       "cancelled_before_request",
		InputTokens:  -1,
		OutputTokens: -1,
	}
	if abortReason != "" {
		outcome.Reason = abortReason
		return outcome, abortReason
	}

	if ctx.Err() != nil {
		outcome.Status = report.OutcomeCancelled
		return outcome, abortReason
	}

	callCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	r.RequestBytes += len(w.raw)

	completion, code := call(callCtx, provider, w.raw)
	if code == "" && callCtx.Err() != nil {
		code = review.ErrorCode(callCtx.Err())
	}

	cancel()

	if code != "" {
		switch code {
		case "http_status_401", "http_status_403", "http_status_404", "http_status_429", "http_status_503", "transport_http_failed", "transport_connection_failed", "transport_dns_failed", "transport_address_not_permitted", "provider_panic":
			abortReason = "provider_circuit_open"
		}

		outcome.Status = report.OutcomeFailed

		outcome.Reason = code
		if code == "cancelled" {
			outcome.Status = report.OutcomeCancelled
		}

		return outcome, abortReason
	}

	raw, metadataCode := bindCompletion(&outcome, completion, o.MaxResponseBytes)
	if metadataCode != "" {
		outcome.Status, outcome.Reason = report.OutcomeFailed, metadataCode
		return outcome, abortReason
	}

	response, code := ValidateResponse(ctx, w.request, raw, o.MaxResponseBytes)
	if code != "" {
		outcome.Status = report.OutcomeFailed
		outcome.Reason = code

		return outcome, abortReason
	}

	acceptResponse(w, response, o, r, &outcome)

	return outcome, abortReason
}

func acceptResponse(w work, response review.Response, o review.Options, r *report.SemanticReport, outcome *report.SemanticOutcome) {
	lookup := map[string]review.Excerpt{}
	for _, x := range w.request.Excerpts {
		lookup[x.ID] = x
	}

	outcome.Status, outcome.Reason = report.OutcomeCompleted, "validated_response"

	r.CompletedRequests++
	for _, x := range response.Proposals {
		if len(r.Proposals) >= o.MaxProposals {
			outcome.Status, outcome.Reason = report.OutcomePartial, "proposal_budget"
			continue
		}

		evidence := references(x.Evidence, lookup)
		identity, _ := json.Marshal(struct {
			Task, Reason, Severity string
			Evidence               []report.SourceRef
		}{Task: w.request.RequestID, Reason: x.Reason, Severity: x.Severity, Evidence: evidence})
		category, _ := proposalCategory(x.Reason)

		proposal := report.SemanticProposal{
			UpstreamRuleID:    knowledge.UpstreamID(x.Reason),
			ID:                artifact.Hash(identity),
			TaskID:            w.request.RequestID,
			Reason:            x.Reason,
			Category:          category,
			SuggestedSeverity: report.Severity(x.Severity),
			Evidence:          evidence,
		}
		if topic, ok := knowledge.TopicForReason(x.Reason); ok {
			proposal.KnowledgeTopicID = topic.ID
			guide, _ := knowledge.GuideForReason(x.Reason)
			proposal.Guidance = &guide
		}

		r.Proposals = append(r.Proposals, proposal)
	}

	for _, x := range response.Assessments {
		if w.request.Mode == knowledge.ModeProposalAssessment {
			r.ProposalAssessments = append(r.ProposalAssessments, report.SemanticProposalAssessment{
				TaskID:     w.request.RequestID,
				ProposalID: x.FindingID,
				Verdict:    x.Verdict,
				Reason:     x.Reason,
				Evidence:   references(x.Evidence, lookup),
			})
		} else {
			r.Assessments = append(r.Assessments, report.SemanticAssessment{
				TaskID:    w.request.RequestID,
				FindingID: x.FindingID,
				Verdict:   x.Verdict,
				Reason:    x.Reason,
				Evidence:  references(x.Evidence, lookup),
			})
		}

		if x.Verdict == review.VerdictInsufficientContext {
			outcome.Status, outcome.Reason = report.OutcomePartial, "assessment_insufficient_context"
		}
	}
}

func finishSemanticReport(r *report.SemanticReport) {
	if len(r.Gaps) > 0 {
		r.Completeness = report.Partial
	}

	for _, o := range r.Outcomes {
		if o.Status != report.OutcomeCompleted {
			r.Completeness = report.Partial
		}
	}

	if len(r.Tasks) > 0 && r.CompletedRequests == 0 {
		r.Completeness = report.Failed
	}
}

func call(ctx context.Context, p review.Provider, raw []byte) (c review.Completion, code string) {
	defer func() {
		if recover() != nil {
			c = review.Completion{}
			code = "provider_panic"
		}
	}()

	c, err := p.Complete(ctx, append([]byte(nil), raw...))
	if err != nil {
		return review.Completion{}, review.ErrorCode(err)
	}

	return c, ""
}

func references(citations []review.Citation, lookup map[string]review.Excerpt) []report.SourceRef {
	refs := make([]report.SourceRef, 0, len(citations))
	for _, c := range citations {
		refs = append(refs, sourceRef(lookup[c.ExcerptID]))
	}

	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}

		if a.ByteStart != b.ByteStart {
			return a.ByteStart < b.ByteStart
		}

		return a.ByteEnd < b.ByteEnd
	})

	return refs
}

// bindCompletion admits bounded provider-controlled metadata, then binds the
// exact response bytes and reported identities to the immutable task outcome.
func bindCompletion(outcome *report.SemanticOutcome, completion review.Completion, maxBytes int) ([]byte, string) {
	if len(completion.Output) > maxBytes {
		return nil, "response_limit"
	}

	if completion.ValidateMetadata() != nil {
		return nil, "invalid_response_metadata"
	}

	raw := append([]byte(nil), completion.Output...)

	outcome.ResponseSHA256 = artifact.Hash(raw)
	if completion.Model != "" {
		outcome.ReportedModelSHA256 = artifact.Hash([]byte(completion.Model))
	}

	if completion.Fingerprint != "" {
		outcome.FingerprintSHA256 = artifact.Hash([]byte(completion.Fingerprint))
	}

	outcome.InputTokens, outcome.OutputTokens = completion.InputTokens, completion.OutputTokens

	return raw, ""
}
