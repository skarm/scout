package report

// SemanticReport contains model proposals and assessments, not deterministic findings.
// No response prose, source bytes, API keys or endpoint URLs enter this contract.
type SemanticReport struct {
	// InstructionPack identifies the compiled instruction assets selected for
	// semantic review.
	InstructionPack KnowledgeManifest `json:"instruction_pack"`
	// InitialTaskCount counts tasks planned before proposal assessment.
	InitialTaskCount int `json:"initial_task_count"`
	// InitialGapCount counts recorded review gaps before proposal assessment.
	InitialGapCount int `json:"initial_gap_count"`
	// InitialOmittedGaps counts omitted review gaps before proposal assessment.
	InitialOmittedGaps int `json:"initial_omitted_gaps"`
	// OmittedGaps counts review gaps omitted by retention limits.
	OmittedGaps int `json:"omitted_gaps"`
	// Enabled records whether semantic review was selected.
	Enabled bool `json:"enabled"`
	// Scope describes the discovery and assessment work covered by this review.
	Scope string `json:"scope"`
	// ProtocolVersion identifies the semantic request and response protocol
	// revision.
	ProtocolVersion string `json:"protocol_version"`
	// PromptVersion identifies the compiled review instruction revision.
	PromptVersion string `json:"prompt_version"`
	// PromptSHA256 identifies the compiled instruction pack used for the review.
	PromptSHA256 string `json:"prompt_sha256"`
	// ResponseSchemaSHA256 identifies the trusted schema used to validate model
	// responses.
	ResponseSchemaSHA256 string `json:"response_schema_sha256"`
	// Provider identifies the explicitly configured review provider.
	Provider ProviderIdentity `json:"provider"`
	// Options records effective review permissions and resource budgets without
	// credentials.
	Options SemanticSettings `json:"options"`
	// VerificationPlanSHA256 identifies the follow-up proposal assessment plan.
	VerificationPlanSHA256 string `json:"verification_plan_sha256,omitempty"`
	// ProposalAssessments records follow-up model verdicts without altering
	// original proposals.
	ProposalAssessments []SemanticProposalAssessment `json:"proposal_assessments"`
	// PlanSHA256 binds the task plan independently of its execution outcomes.
	PlanSHA256 string `json:"plan_sha256,omitempty"`
	// Completeness records coverage of the selected work, independently of
	// findings and policy.
	Completeness Completeness `json:"completeness,omitempty"`
	// Tasks contains the planned review and follow-up assessment tasks.
	Tasks []SemanticTask `json:"tasks"`
	// Outcomes contains the execution outcome for each planned review task.
	Outcomes []SemanticOutcome `json:"outcomes"`
	// Gaps records review work that was not completed or could not be validated.
	Gaps []SemanticGap `json:"gaps"`
	// Proposals records validated model hypotheses separately from deterministic
	// findings.
	Proposals []SemanticProposal `json:"proposals"`
	// Assessments records model verdicts about existing observations.
	Assessments []SemanticAssessment `json:"assessments"`
	// RequestBytes counts user-request bytes passed to provider calls, including
	// failed calls.
	RequestBytes int `json:"request_bytes"`
	// CompletedRequests counts validated provider responses, including responses
	// whose proposals were later truncated.
	CompletedRequests int `json:"completed_requests"`
}

// SemanticTask binds a planned review request to its mode, evidence and
// compiled instruction digest.
type SemanticTask struct {
	// KnowledgeTopicIDs lists compiled review lenses included in the task's
	// instructions.
	KnowledgeTopicIDs []string `json:"knowledge_topic_ids"`
	// PromptSHA256 hashes the complete compiled instructions for this task's mode.
	PromptSHA256 string `json:"prompt_sha256"`
	// PromptBytes records the byte length of the task's compiled instruction.
	PromptBytes int `json:"prompt_bytes"`
	// DependsOn lists prerequisite task identities.
	DependsOn []string `json:"depends_on,omitempty"`
	// ProposalIDs lists hypotheses selected for follow-up assessment.
	ProposalIDs []string `json:"proposal_ids,omitempty"`
	// ScopeID binds the task to its selected review scope.
	ScopeID string `json:"scope_id"`
	// ID identifies a planned review request and binds its outcome to the plan.
	ID string `json:"id"`
	// Mode selects one supported semantic review stage.
	Mode string `json:"mode"`
	// RequestSHA256 identifies the exact serialized user request.
	RequestSHA256 string `json:"request_sha256"`
	// RequestBytes is the serialized user request size, excluding system
	// instructions and provider envelopes.
	RequestBytes int `json:"request_bytes"`
	// Inputs records scanner-issued inputs and their source spans.
	Inputs []SemanticInput `json:"inputs"`
	// FindingIDs lists findings supplied to the review task.
	FindingIDs []string `json:"finding_ids"`
	// LinkIDs lists component relationships supplied to the review task.
	LinkIDs []string `json:"link_ids"`
}

// SemanticInput binds a scanner-issued input identity to a source span.
type SemanticInput struct {
	// ID is the scanner-issued excerpt identity available for request-scoped
	// citations.
	ID string `json:"id"`
	// Source binds the scanner-issued input to exact source bytes and offsets.
	Source SourceRef `json:"source"`
}

// SemanticOutcome records one review task's result and unverified
// provider-reported usage metadata.
type SemanticOutcome struct {
	// TaskID identifies the planned task associated with this result.
	TaskID string `json:"task_id"`
	// Status records whether the review task completed, failed, was cancelled or
	// did not run.
	Status string `json:"status"`
	// Reason records the bounded reason for the outcome.
	Reason string `json:"reason"`
	// ResponseSHA256 identifies the accepted response bytes without retaining
	// response prose.
	ResponseSHA256 string `json:"response_sha256,omitempty"`
	// ReportedModelSHA256 identifies the server-reported model label without
	// retaining its text.
	ReportedModelSHA256 string `json:"reported_model_sha256,omitempty"`
	// FingerprintSHA256 identifies optional server-reported fingerprint metadata.
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	// InputTokens records server-reported input tokens; -1 means not reported. The
	// count is not independently verified.
	InputTokens int64 `json:"reported_input_tokens"`
	// OutputTokens records server-reported output tokens; -1 means not reported.
	// The count is not independently verified.
	OutputTokens int64 `json:"reported_output_tokens"`
}

// SemanticGap identifies review work that could not be completed or validated.
type SemanticGap struct {
	// ProposalID identifies the semantic hypothesis associated with this result.
	ProposalID string `json:"proposal_id,omitempty"`
	// Code is a stable machine-readable condition identifier.
	Code string `json:"code"`
	// Path identifies the source object affected by the review gap, when known.
	Path string `json:"path,omitempty"`
	// ByteStart is the inclusive, zero-based byte offset in the referenced object.
	ByteStart int `json:"byte_start,omitempty"`
	// ByteEnd is the exclusive, zero-based byte offset in the referenced object.
	ByteEnd int `json:"byte_end,omitempty"`
	// FindingID identifies the static finding whose assessment is incomplete, when
	// applicable.
	FindingID string `json:"finding_id,omitempty"`
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id,omitempty"`
}

// SemanticProposal records a validated model hypothesis separately from
// deterministic findings.
type SemanticProposal struct {
	// KnowledgeTopicID identifies the compiled review lens selected by the
	// validated reason.
	KnowledgeTopicID string `json:"knowledge_topic_id,omitempty"`
	// Guidance contains the compiled guide selected by the accepted reason code.
	Guidance *Guidance `json:"guidance,omitempty"`
	// UpstreamRuleID records the adapted upstream identity derived locally from
	// the validated reason.
	UpstreamRuleID string `json:"upstream_rule_id,omitempty"`
	// ID identifies an accepted hypothesis for follow-up assessment without
	// changing its evidence.
	ID string `json:"id"`
	// TaskID identifies the planned task associated with this result.
	TaskID string `json:"task_id"`
	// Reason is the accepted mode-specific reason code for this hypothesis.
	Reason string `json:"reason"`
	// Category is the concern category derived locally from Reason.
	Category string `json:"category"`
	// SuggestedSeverity records model-suggested impact, separate from
	// deterministic finding severity.
	SuggestedSeverity Severity `json:"suggested_severity"`
	// Evidence contains source spans resolved from the proposal's validated
	// citations.
	Evidence []SourceRef `json:"evidence"`
}

// SemanticAssessment records a model's assessment of an existing finding
// without changing that finding.
type SemanticAssessment struct {
	// TaskID identifies the planned task associated with this result.
	TaskID string `json:"task_id"`
	// FindingID identifies the static finding assessed by this verdict.
	FindingID string `json:"finding_id"`
	// Verdict records the validated model assessment outcome.
	Verdict string `json:"verdict"`
	// Reason is the validated reason code explaining the verdict.
	Reason string `json:"reason"`
	// Evidence contains source spans resolved from the assessment's validated
	// citations.
	Evidence []SourceRef `json:"evidence"`
}

// SemanticProposalAssessment records a second model pass, not an independent security proof.
// Original proposal identity/evidence/severity remains unchanged for all verdicts.
type SemanticProposalAssessment struct {
	// TaskID identifies the planned task associated with this result.
	TaskID string `json:"task_id"`
	// ProposalID identifies the semantic hypothesis associated with this result.
	ProposalID string `json:"proposal_id"`
	// Verdict records the validated model assessment outcome.
	Verdict string `json:"verdict"`
	// Reason is the validated reason code explaining the follow-up verdict.
	Reason string `json:"reason"`
	// Evidence contains source spans supporting the follow-up verdict.
	Evidence []SourceRef `json:"evidence"`
}
