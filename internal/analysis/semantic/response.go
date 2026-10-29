package semantic

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/review"
)

const reasonResponseSchema = "response_schema"

const invalidAssessmentReason = "invalid_assessment_reason"

//nolint:gochecknoglobals // Read-only response and applicability grammar shared by review requests.
var assessmentReasons = map[string][]string{
	review.VerdictConfirmed: {review.AssessmentSupportedByContext}, review.VerdictDisputed: {review.AssessmentBenignExample, review.AssessmentLegitimateUse},
	review.VerdictInsufficientContext: {review.AssessmentInsufficientContext},
}

//nolint:gochecknoglobals // Read-only response and applicability grammar shared by review requests.
var responseModes = map[string]bool{
	knowledge.ModeAssessment: true, knowledge.ModeProposalAssessment: true,
	knowledge.ModeDiscovery: false, knowledge.ModeIntent: false, knowledge.ModeQuality: false, knowledge.ModeToolConsistency: false,
}

// ValidateResponse checks the exact protocol and evidence of ONE immutable task.
// Parsing success/JSON Schema alone is insufficient. No permissive repair or
// partial acceptance: malformed tasks are failed, prior task results retained.
func ValidateResponse(ctx context.Context, request review.Request, raw []byte, maxBytes int) (review.Response, string) {
	bad := func(code string) (review.Response, string) { return review.Response{}, code }
	if maxBytes < 1 || len(raw) > maxBytes {
		return bad("response_limit")
	}

	root, err := jsonconfig.Parse(ctx, string(raw))
	if err != nil {
		return bad("invalid_response_json")
	}

	if code := responseShape(root); code != "" {
		return bad(code)
	}

	var out review.Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return bad(reasonResponseSchema)
	}

	if out.SchemaVersion != review.ProtocolVersion || out.RequestID != request.RequestID {
		return bad("response_identity_mismatch")
	}

	if code := validateResponseEvidence(request, out); code != "" {
		return bad(code)
	}

	return out, ""
}

func responseItemsShape(root *jsonconfig.Node) bool {
	for _, grammar := range []struct {
		collection *jsonconfig.Node
		strings    []string
	}{
		{collection: root.Get("proposals"), strings: []string{"reason", "severity"}},
		{collection: root.Get("assessments"), strings: []string{"finding_id", "verdict", "reason"}},
	} {
		keys := append(slices.Clone(grammar.strings), "evidence")
		for _, item := range grammar.collection.Elements {
			if !object(item, keys...) || !citationsShape(item.Get("evidence")) {
				return false
			}

			for _, key := range grammar.strings {
				if !text(item.Get(key)) {
					return false
				}
			}
		}
	}

	return true
}

func validateResponseEvidence(request review.Request, out review.Response) string {
	excerpts := make(map[string]string, len(request.Excerpts))
	for _, s := range request.Excerpts {
		if _, ok := excerpts[s.ID]; ok {
			return "invalid_request_evidence"
		}

		excerpts[s.ID] = s.SHA256
	}

	check := func(cs []review.Citation) bool {
		seen := map[string]bool{}

		for _, c := range cs {
			hash, ok := excerpts[c.ExcerptID]
			if !ok || c.SHA256 != hash || seen[c.ExcerptID] {
				return false
			}

			seen[c.ExcerptID] = true
		}

		return true
	}
	if code := validateProposals(request, out.Proposals, check); code != "" {
		return code
	}

	return validateAssessments(request, out, check)
}

func validateProposals(request review.Request, proposals []review.Proposal, check func([]review.Citation) bool) string {
	seenProposals := map[string]bool{}

	for _, p := range proposals {
		if code := proposalScope(request, p); code != "" {
			return code
		}

		if !slices.Contains([]string{"low", "medium", "high", "critical"}, p.Severity) {
			return "invalid_severity"
		}

		if !check(p.Evidence) {
			return "evidence_outside_request"
		}

		if request.Mode == knowledge.ModeQuality && !qualityApplies(p.Reason, p.Evidence, request.Excerpts) {
			return "quality_applicability_unverified"
		}

		ids := make([]string, 0, len(p.Evidence))
		for _, c := range p.Evidence {
			ids = append(ids, c.ExcerptID)
		}

		sort.Strings(ids)

		key := p.Reason + "\x00" + strings.Join(ids, "\x00")
		if seenProposals[key] {
			return "duplicate_proposal"
		}

		seenProposals[key] = true
	}

	return ""
}

func validateAssessments(request review.Request, out review.Response, check func([]review.Citation) bool) string {
	expected := map[string]review.Finding{}
	for _, f := range request.Findings {
		expected[f.ID] = f
	}

	seen := map[string]bool{}

	for _, a := range out.Assessments {
		f, ok := expected[a.FindingID]
		if !ok || seen[a.FindingID] {
			return "unknown_or_duplicate_finding"
		}

		seen[a.FindingID] = true
		if !check(a.Evidence) {
			return "evidence_outside_request"
		}

		if !assessmentCoversTarget(a.Evidence, f.Evidence) {
			return "target_evidence_missing"
		}

		if code := validateVerdict(a); code != "" {
			return code
		}
	}

	return validateResponseMode(request, out, len(seen), len(expected))
}

func validateVerdict(a review.Assessment) string {
	reasons, known := assessmentReasons[a.Verdict]
	if !known {
		return "invalid_assessment_verdict"
	}

	if !slices.Contains(reasons, a.Reason) {
		return invalidAssessmentReason
	}

	return ""
}

func validateResponseMode(request review.Request, out review.Response, seen, expected int) string {
	assessment, known := responseModes[request.Mode]
	if !known {
		return "invalid_request_mode"
	}

	if assessment {
		if len(out.Proposals) > 0 || len(request.Findings) == 0 || seen != expected {
			return "missing_assessment_or_wrong_mode"
		}
	} else if len(out.Assessments) > 0 || len(request.Findings) > 0 {
		return "wrong_response_mode"
	}

	return ""
}

func proposalCategory(reason string) (string, bool) {
	d, ok := knowledge.LookupReason(reason)
	return d.Category, ok
}

func object(n *jsonconfig.Node, keys ...string) bool {
	if n == nil || n.Kind != jsonconfig.KindObject || len(n.Members) != len(keys) {
		return false
	}

	for _, k := range keys {
		if n.Get(k) == nil {
			return false
		}
	}

	return true
}
func text(n *jsonconfig.Node) bool { return n != nil && n.Kind == jsonconfig.KindString }
func citationsShape(n *jsonconfig.Node) bool {
	if n == nil || n.Kind != jsonconfig.KindArray || len(n.Elements) < 1 || len(n.Elements) > review.MaxEvidence {
		return false
	}

	for _, c := range n.Elements {
		if !object(c, "excerpt_id", "sha256") || !text(c.Get("excerpt_id")) || !text(c.Get("sha256")) {
			return false
		}
	}

	return true
}

func responseShape(root *jsonconfig.Node) string {
	if !object(root, "schema_version", "request_id", "proposals", "assessments") {
		return reasonResponseSchema
	}

	for _, key := range []string{"schema_version", "request_id"} {
		if !text(root.Get(key)) {
			return reasonResponseSchema
		}
	}

	for _, key := range []string{"proposals", "assessments"} {
		node := root.Get(key)
		if node.Kind != jsonconfig.KindArray {
			return reasonResponseSchema
		}
	}

	for _, key := range []string{"proposals", "assessments"} {
		if len(root.Get(key).Elements) > review.MaxItems {
			return "response_item_limit"
		}
	}

	if !responseItemsShape(root) {
		return reasonResponseSchema
	}

	return ""
}

func proposalScope(request review.Request, p review.Proposal) string {
	if _, ok := proposalCategory(p.Reason); !ok {
		return "invalid_reason"
	}

	if (request.Mode == knowledge.ModeQuality) != strings.HasPrefix(p.Reason, "quality_") {
		return "wrong_quality_scope"
	}

	if mode := knowledge.ReasonMode(p.Reason); mode != "" && request.Mode != mode {
		return "wrong_specialized_scope"
	}

	if request.Mode == knowledge.ModeToolConsistency {
		if p.Reason != "tool_description_code_mismatch" || !toolConsistencyEvidence(p.Evidence, request.Excerpts) {
			return "tool_consistency_evidence_or_scope"
		}
	}

	return ""
}

func assessmentCoversTarget(actual, expected []review.Citation) bool {
	cited := map[string]bool{}
	for _, c := range actual {
		cited[c.ExcerptID] = true
	}

	for _, c := range expected {
		if !cited[c.ExcerptID] {
			return false
		}
	}

	return true
}
