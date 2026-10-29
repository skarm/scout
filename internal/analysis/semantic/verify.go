package semantic

import (
	"encoding/json"
	"slices"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

type verificationParent struct {
	work     work
	evidence evidenceIndex
}

// planVerification constructs a NEW, evidence-bound phase after discovery.
// The initial plan is never rewritten. All verification tasks are fixed before
// the first verification call. Budgets are shared with the first phase; they
// are NOT reset for each proposal or phase. A missing task becomes a named gap.
func (p *planner) planVerification(proposals []report.SemanticProposal, initialPlan string) ([]work, string) {
	start, gapStart, omittedStart := len(p.works), len(p.gaps), p.omittedGaps

	parents := make(map[string]verificationParent, start)
	for _, w := range p.works {
		parents[w.metadata.ID] = verificationParent{work: w, evidence: indexEvidence(w.request.Excerpts)}
	}

	for _, proposal := range proposals {
		if p.ctx.Err() != nil {
			p.proposalGap("proposal_assessment_cancelled", proposal.ID)
			continue
		}

		parent, ok := parents[proposal.TaskID]
		if !ok || !slices.Contains([]string{knowledge.ModeDiscovery, knowledge.ModeIntent, knowledge.ModeQuality, knowledge.ModeToolConsistency}, parent.work.request.Mode) {
			p.proposalGap("proposal_parent_missing", proposal.ID)
			continue
		}

		req, valid := p.verificationRequest(parent, proposal)
		if !valid {
			p.proposalGap("proposal_evidence_missing", proposal.ID)
			continue
		}

		if code := p.add(req); code != "" {
			p.proposalGap("proposal_assessment_"+code, proposal.ID)
		}
	}

	tasks := make([]report.SemanticTask, 0, len(p.works)-start)
	for _, w := range p.works[start:] {
		tasks = append(tasks, w.metadata)
	}

	raw, _ := json.Marshal(struct {
		Phase      string
		ParentPlan string
		Proposals  []report.SemanticProposal
		Tasks      []report.SemanticTask
		Gaps       []report.SemanticGap
		Omitted    int
	}{
		Phase:      "proposal-assessment-v1",
		ParentPlan: initialPlan,
		Proposals:  proposals,
		Tasks:      tasks,
		Gaps:       p.gaps[gapStart:],
		Omitted:    p.omittedGaps - omittedStart,
	})

	return p.works[start:], artifact.Hash(raw)
}

func (p *planner) proposalGap(code, proposalID string) {
	if len(p.gaps) >= 4096 {
		p.omittedGaps++
		return
	}

	p.gaps = append(p.gaps, report.SemanticGap{Code: code, ProposalID: proposalID})
}

func (p *planner) verificationRequest(parent verificationParent, proposal report.SemanticProposal) (review.Request, bool) {
	// Reuse the complete ORIGINAL bounded context, not a summary or model
	// explanation. Only the fixed reason/severity is supplied as a hypothesis.
	req := p.request(knowledge.ModeProposalAssessment)
	req.ScopeID, req.ParentTaskID = parent.work.request.ScopeID, parent.work.metadata.ID
	req.Excerpts = append(req.Excerpts, parent.work.request.Excerpts...)
	req.Links = append(req.Links, parent.work.request.Links...)

	evidence := make([]review.Citation, 0, len(proposal.Evidence))
	for _, ref := range proposal.Evidence {
		if citation, ok := parent.evidence.exact[ref]; ok {
			evidence = append(evidence, citation)
		}
	}

	if len(evidence) == 0 || len(evidence) != len(proposal.Evidence) || len(evidence) > review.MaxEvidence {
		return req, false
	}

	req.Findings = []review.Finding{{
		ID:       proposal.ID,
		Origin:   "semantic_proposal",
		Reason:   proposal.Reason,
		Category: proposal.Category,
		Severity: string(proposal.SuggestedSeverity),
		Evidence: evidence,
	}}
	if guide, ok := knowledge.GuideForReason(proposal.Reason); ok {
		req.Findings[0].Guidance = &guide
	}

	return req, true
}
