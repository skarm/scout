// Package review defines the tool-free, opt-in semantic review protocol.
// Source bytes in Request are sensitive. Providers are trusted caller-supplied
// transports, not code discovered inside an artifact. Implementations must be
// concurrency-safe, honor context cancellation and never execute returned code.
package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/scout/internal/reviewpack"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

const (
	// ProtocolVersion identifies the supported semantic request and response
	// protocol.
	ProtocolVersion = "5"
	// PromptVersion identifies instruction compatibility; PromptDigest identifies
	// the exact instruction contents.
	PromptVersion = reviewpack.InstructionsVersion
	// MaxRequestBytes bounds serialized review requests at every transport boundary.
	MaxRequestBytes = 128 << 10
	// MaxSegments bounds excerpts in one review request.
	MaxSegments = 64
	// MaxItems limits each proposals or assessments array in a review response.
	MaxItems = 16
	// MaxEvidence bounds citations attached to one proposal or assessment.
	MaxEvidence = 8
)

const (
	// VerdictConfirmed means the supplied evidence supports the observation.
	VerdictConfirmed = "confirmed"
	// VerdictDisputed means the supplied evidence supports a benign interpretation.
	VerdictDisputed = "disputed"
	// VerdictInsufficientContext means the supplied evidence cannot settle the observation.
	VerdictInsufficientContext = "insufficient_context"
	// AssessmentSupportedByContext explains a confirmed verdict.
	AssessmentSupportedByContext = "supported_by_context"
	// AssessmentBenignExample explains a disputed verdict based on example context.
	AssessmentBenignExample = "benign_example"
	// AssessmentLegitimateUse explains a disputed verdict based on legitimate use.
	AssessmentLegitimateUse = "legitimate_use"
	// AssessmentInsufficientContext records insufficient evidence for a verdict.
	AssessmentInsufficientContext = "insufficient_context"
)

const baseResponseSchema = `{
 "type":"object", "additionalProperties":false,
 "required":["schema_version","request_id","proposals","assessments"],
 "properties":{
  "schema_version":{"type":"string","enum":[]},
  "request_id":{"type":"string"},
  "proposals":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["reason","severity","evidence"],"properties":{
   "reason":{"type":"string","enum":[]},
   "severity":{"type":"string","enum":[]},"evidence":{"$ref":"#/$defs/evidence"}}}},
  "assessments":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["finding_id","verdict","reason","evidence"],"properties":{
   "finding_id":{"type":"string"},"verdict":{"type":"string","enum":[]},
   "reason":{"type":"string","enum":[]},"evidence":{"$ref":"#/$defs/evidence"}}}}
 },
 "$defs":{"evidence":{"type":"array","minItems":1,"items":{"type":"object","additionalProperties":false,"required":["excerpt_id","sha256"],"properties":{"excerpt_id":{"type":"string"},"sha256":{"type":"string"}}}}}
}`

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var responseSchema = compiledResponseSchema()

// Options are operator-owned; no field is loaded from the inspected package.
// Enabled makes every scheduled semantic task required. Zero value is offline.
type Options struct {
	// QualityPolicy selects the separate opt-in quality-policy review stage.
	QualityPolicy bool `json:"quality_policy"`
	// Enabled requires scheduled semantic tasks to complete; enabling it also
	// requires AllowSourceUpload.
	Enabled bool `json:"enabled"`
	// AllowSourceUpload records explicit operator consent to send bounded source
	// excerpts to a reviewer.
	AllowSourceUpload bool `json:"allow_source_upload"`
	// MaxRequests bounds service requests, including requests that fail.
	MaxRequests int `json:"max_requests"`
	// MaxInputBytes bounds the sum of serialized user-request bytes across review
	// tasks.
	MaxInputBytes int `json:"max_input_bytes"`
	// MaxRequestBytes bounds one serialized user request, excluding the trusted
	// system instruction and provider envelope.
	MaxRequestBytes int `json:"max_request_bytes"`
	// MaxResponseBytes bounds accepted response bytes.
	MaxResponseBytes int `json:"max_response_bytes"`
	// MaxProposals bounds retained semantic hypotheses.
	MaxProposals int `json:"max_proposals"`
	// ChunkBytes bounds source excerpt chunks prepared for review.
	ChunkBytes int `json:"chunk_bytes"`
	// Timeout bounds each semantic provider request, within the caller's overall
	// context deadline.
	Timeout time.Duration `json:"timeout_ns"`
}

// Identity describes requested configuration, not proof of the model actually
// executing on the remote server. EndpointSHA256 excludes credentials.
type Identity struct {
	// Provider identifies the explicitly configured review provider.
	Provider string `json:"provider"`
	// Model records the requested model identity rather than proving the executing
	// model.
	Model string `json:"requested_model"`
	// EndpointSHA256 identifies the configured endpoint without exposing its URL
	// or credentials.
	EndpointSHA256 string `json:"endpoint_sha256,omitempty"`
	// SettingsSHA256 identifies the selected provider or routing configuration.
	SettingsSHA256 string `json:"settings_sha256,omitempty"`
}

// Provider receives its own copy of a bounded JSON request. It cannot mutate the
// planner's source evidence or report. No raw provider errors enter scan reports.
type Provider interface {
	// Identity returns bounded requested configuration without credentials or raw
	// endpoint URLs.
	Identity() Identity
	// Complete receives an independent JSON request and returns response bytes
	// under ctx. Implementations must honor cancellation.
	Complete(context.Context, []byte) (Completion, error)
}

// Completion contains one provider response and optional, unverified server
// metadata.
type Completion struct {
	// Output contains provider response bytes that still require request-scoped
	// protocol validation.
	Output []byte
	// Model is the server-reported model label, which is not independently
	// verified.
	Model string
	// Fingerprint is optional server-reported metadata, not a verified model
	// identity.
	Fingerprint string
	InputTokens int64 // -1 means not reported; server supplied, not independently verified
	// OutputTokens records server-reported output tokens; -1 means not reported.
	// The count is not independently verified.
	OutputTokens int64
}

// Request binds a semantic task to its instruction identity and scanner-issued
// evidence.
type Request struct {
	// PromptSHA256 must match the compiled instructions selected for Mode.
	PromptSHA256 string `json:"prompt_sha256"`
	// ParentTaskID identifies the originating task for a follow-up review request.
	ParentTaskID string `json:"parent_task_id,omitempty"`
	// ScopeID identifies the component or document scope being reviewed.
	ScopeID string `json:"scope_id"`
	// SchemaVersion identifies the versioned schema used by this contract.
	SchemaVersion string `json:"schema_version"`
	// PromptVersion identifies the compiled review instruction revision.
	PromptVersion string `json:"prompt_version"`
	// RequestID binds the response to the originating scanner-issued request.
	RequestID string `json:"request_id"`
	// Mode selects discovery, intent, tool_consistency, assessment,
	// proposal_assessment or quality.
	Mode string `json:"mode"`
	// SnapshotSHA256 binds the request to the captured inventory identity.
	SnapshotSHA256 string `json:"snapshot_sha256"`
	// Harness records the selected host interpretation for the reviewer.
	Harness string `json:"harness"`
	// Excerpts contains bounded original or derived source bytes selected by the
	// scanner.
	Excerpts []Excerpt `json:"excerpts"`
	// Findings contains static findings or hypotheses supplied for assessment.
	Findings []Finding `json:"findings"`
	// Links contains source-bound component relationships relevant to the task.
	Links []Link `json:"links"`
	// Components contains the component declarations supplied as review context.
	Components []Component `json:"components"`
}

// Excerpt holds bounded contiguous original/derived bytes. No normalization or
// fabricated coordinates. IDs bind the exact object, span and content hash.
type Excerpt struct {
	ContentKind string `json:"content_kind"` // scanner hint, not proof of runtime role
	// ID binds this request's source excerpt to its object, span and exact bytes.
	ID string `json:"id"`
	// Path is the inventory path of the object containing Text.
	Path string `json:"path"`
	// ObjectSHA256 identifies the complete object from which the excerpt was
	// taken.
	ObjectSHA256 string `json:"object_sha256"`
	// ByteStart is the inclusive, zero-based byte offset in the referenced object.
	ByteStart int `json:"byte_start"`
	// ByteEnd is the exclusive, zero-based byte offset in the referenced object.
	ByteEnd int `json:"byte_end"`
	// SHA256 identifies the exact excerpt bytes that citations must match.
	SHA256 string `json:"sha256"`
	// Text contains the exact selected source bytes as text without normalization.
	Text string `json:"text"`
	// Components lists component IDs associated with the excerpt.
	Components []string `json:"components"`
}

// Finding is an assessment target, NOT necessarily a deterministic finding.
// Origin distinguishes static evidence from an untrusted semantic hypothesis.
type Finding struct {
	// Guidance contains Scout's compiled guide for the finding or hypothesis under
	// assessment.
	Guidance *knowledge.Guide `json:"guidance,omitempty"`
	// ContextSignals supplies source-context hints for assessment without changing
	// the original finding.
	ContextSignals []string `json:"context_signals,omitempty"`
	// Origin identifies whether the observation comes from static analysis or a
	// semantic hypothesis.
	Origin string `json:"origin"`
	// Reason records the locally validated semantic reason for a hypothesis, when
	// applicable.
	Reason string `json:"reason,omitempty"`
	// Category is the concern category assigned by Scout.
	Category string `json:"category,omitempty"`
	// Method identifies how the assessed observation was produced.
	Method string `json:"method,omitempty"`
	// Description is the scanner-authored description supplied for assessment.
	Description string `json:"description,omitempty"`
	// ID selects the static finding or semantic hypothesis to assess in this
	// request.
	ID string `json:"id"`
	// RuleID identifies the originating static check or adapted hypothesis
	// taxonomy.
	RuleID string `json:"rule_id"`
	// Severity records the finding's impact independently of execution state or
	// policy.
	Severity string `json:"severity"`
	// Evidence cites excerpts in this request that support the assessed
	// observation.
	Evidence []Citation `json:"evidence"`
}

// Component is the bounded component context supplied to a reviewer.
type Component struct {
	// ID identifies a component supplied in this review request.
	ID string `json:"id"`
	// Kind is the declaration kind, such as a skill, hook or tool.
	Kind string `json:"kind"`
	// Host identifies the host interpretation used for the declaration.
	Host string `json:"host"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
}

// Link describes a component relationship with citations to scanner-issued
// excerpts.
type Link struct {
	// ID identifies a component relationship supplied in this review request.
	ID string `json:"id"`
	// From identifies the source component of the relationship.
	From string `json:"from"`
	// To identifies the destination component of the relationship.
	To string `json:"to"`
	// Relation identifies the relationship between From and To.
	Relation string `json:"relation"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
	// Evidence cites excerpts supporting the component relationship.
	Evidence []Citation `json:"evidence"`
}

// Citation can only select a scanner-issued excerpt and copy its digest. Models
// need not compute cryptographic hashes or count UTF-8 bytes to cite evidence.
type Citation struct {
	// ExcerptID selects a scanner-issued excerpt from the current request.
	ExcerptID string `json:"excerpt_id"`
	// SHA256 must equal the selected excerpt's scanner-issued SHA-256 digest.
	SHA256 string `json:"sha256"`
}

// Proposal is an untrusted model hypothesis that must pass local taxonomy and
// citation validation.
type Proposal struct {
	// Reason is a compiled reason code allowed for the request's review mode.
	Reason string `json:"reason"`
	// Severity records the finding's impact independently of execution state or
	// policy.
	Severity string `json:"severity"`
	// Evidence cites excerpts supporting the proposed concern.
	Evidence []Citation `json:"evidence"`
}

// Assessment is a model verdict about a supplied finding, with request-scoped
// citations.
type Assessment struct {
	// FindingID selects an assessment target from the current request.
	FindingID string `json:"finding_id"`
	// Verdict records the validated model assessment outcome.
	Verdict string `json:"verdict"`
	// Reason explains the verdict using an allowed assessment reason code.
	Reason string `json:"reason"`
	// Evidence cites excerpts supporting the verdict.
	Evidence []Citation `json:"evidence"`
}

// Response is the versioned semantic response envelope, validated against its
// originating request.
type Response struct {
	// SchemaVersion identifies the versioned schema used by this contract.
	SchemaVersion string `json:"schema_version"`
	// RequestID binds the response to the originating scanner-issued request.
	RequestID string `json:"request_id"`
	// Proposals records validated model hypotheses separately from deterministic
	// findings.
	Proposals []Proposal `json:"proposals"`
	// Assessments records model verdicts about existing observations.
	Assessments []Assessment `json:"assessments"`
}

type optionRange struct {
	value, min, max int64
	message         string
}

// DefaultOptions returns review budgets with semantic review and source upload
// disabled.
func DefaultOptions() Options {
	return Options{
		MaxRequests: 64, MaxInputBytes: 2 << 20, MaxRequestBytes: 32 << 10,
		MaxResponseBytes: 64 << 10, MaxProposals: 128, ChunkBytes: 8 << 10, Timeout: 30 * time.Second,
	}
}

// ResponseSchema returns an independent copy of the compiled response schema
// for JSON schema APIs.
func ResponseSchema() map[string]any {
	var s map[string]any
	if err := json.Unmarshal([]byte(responseSchema), &s); err != nil {
		panic(fmt.Sprintf("invalid compiled protocol schema: %v", err))
	}

	return s
}

// Validate checks review budgets and requires source-upload consent when
// review is enabled.
func (o Options) Validate() error {
	if !o.Enabled {
		if o.QualityPolicy {
			return errors.New("quality policy requires semantic review")
		}

		return nil
	}

	if !o.AllowSourceUpload {
		return errors.New("semantic review requires explicit consent to send source content, which may contain secrets")
	}

	return validateRanges([]optionRange{
		{value: int64(o.MaxRequests), min: 1, max: 256, message: "semantic requests must be in 1..256"},
		{
			value:   int64(o.MaxRequestBytes),
			min:     2048,
			max:     MaxRequestBytes,
			message: "invalid semantic request or aggregate input budget",
		},
		{
			value:   int64(o.MaxInputBytes),
			min:     int64(o.MaxRequestBytes),
			max:     8 << 20,
			message: "invalid semantic request or aggregate input budget",
		},
		{
			value:   int64(o.MaxResponseBytes),
			min:     512,
			max:     128 << 10,
			message: "invalid semantic response or proposal budget",
		},
		{value: int64(o.MaxProposals), min: 1, max: 1024, message: "invalid semantic response or proposal budget"},
		{
			value:   int64(o.ChunkBytes),
			min:     256,
			max:     int64(min(16<<10, o.MaxRequestBytes/2)),
			message: "semantic chunk size must be 256..16384 and at most half the request budget",
		},
		{
			value:   int64(o.Timeout),
			min:     1,
			max:     int64(2 * time.Minute),
			message: "semantic request timeout must be positive and at most 2m",
		},
	})
}

// Validate checks bounded provider and model identifiers and optional digest
// syntax.
func (i Identity) Validate() error {
	for _, s := range []string{i.Provider, i.Model} {
		if len(s) == 0 || len(s) > 128 {
			return errors.New("provider and requested model must contain 1..128 identifier bytes")
		}

		if !textmatch.Token(s, 128, "_.:/@-") {
			return errors.New("invalid provider/model identifier")
		}
	}

	for _, s := range []string{i.EndpointSHA256, i.SettingsSHA256} {
		if s != "" && !textmatch.LowerHex(s, 64) {
			return errors.New("invalid provider configuration digest")
		}
	}

	return nil
}

func validateRanges(ranges []optionRange) error {
	for _, r := range ranges {
		if r.value < r.min || r.value > r.max {
			return errors.New(r.message)
		}
	}

	return nil
}

func compiledResponseSchema() string {
	var schema map[string]any
	if err := json.Unmarshal([]byte(baseResponseSchema), &schema); err != nil {
		panic("invalid base review schema")
	}

	properties := schemaObject(schema, "properties")
	schemaObject(properties, "schema_version")["enum"] = []string{ProtocolVersion}
	proposalArray := schemaObject(properties, "proposals")
	assessmentArray := schemaObject(properties, "assessments")
	proposalArray["maxItems"], assessmentArray["maxItems"] = MaxItems, MaxItems
	evidence := schemaObject(schemaObject(schema, "$defs"), "evidence")
	evidence["maxItems"] = MaxEvidence
	proposals := schemaObject(proposalArray, "items")
	proposalProperties := schemaObject(proposals, "properties")
	schemaObject(proposalProperties, "severity")["enum"] = []report.Severity{report.Low, report.Medium, report.High, report.Critical}
	assessmentProperties := schemaObject(schemaObject(assessmentArray, "items"), "properties")
	schemaObject(assessmentProperties, "verdict")["enum"] = []string{VerdictConfirmed, VerdictDisputed, VerdictInsufficientContext}
	schemaObject(assessmentProperties, "reason")["enum"] = []string{AssessmentSupportedByContext, AssessmentBenignExample, AssessmentLegitimateUse, AssessmentInsufficientContext}
	reason := schemaObject(schemaObject(proposals, "properties"), "reason")

	values, ok := reason["enum"].([]any)
	if !ok {
		panic("invalid base review schema enum")
	}

	for _, value := range knowledge.Reasons() {
		values = append(values, value)
	}

	reason["enum"] = values

	raw, err := json.Marshal(schema)
	if err != nil {
		panic("invalid compiled review schema")
	}

	return string(raw)
}

func schemaObject(parent map[string]any, key string) map[string]any {
	object, ok := parent[key].(map[string]any)
	if !ok {
		panic("invalid base review schema object")
	}

	return object
}
