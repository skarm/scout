package report

import "time"

// GuidanceReference identifies a guidance source and the stated relationship
// to an upstream check.
type GuidanceReference struct {
	// URL locates the cited guidance source.
	URL string `json:"url"`
	// Symbol identifies the cited rule, topic or source symbol.
	Symbol string `json:"symbol"`
	// UpstreamID records an adapted upstream identity without claiming detector
	// equivalence.
	UpstreamID string `json:"upstream_id,omitempty"`
	// Relationship states how Scout's material relates to the referenced source.
	Relationship string `json:"relationship"`
}

// Guidance contains a check's explanation, remediation, review questions and
// source references.
type Guidance struct {
	// Explanation describes the observed risk and the check's interpretation.
	Explanation string `json:"explanation"`
	// Remediation contains compiled guidance for addressing the concern.
	Remediation string `json:"remediation"`
	// ReviewChecks lists questions for reviewing the concern in context.
	ReviewChecks []string `json:"review_checks"`
	// BenignConsiderations lists legitimate contexts to consider without
	// automatically trusting them.
	BenignConsiderations []string `json:"benign_considerations"`
	// Sources identifies reference material and the stated relationship to it.
	Sources []GuidanceReference `json:"sources"`
}

// PromptDescriptor identifies the compiled instructions selected for a review
// mode.
type PromptDescriptor struct {
	// Mode identifies the review stage that uses these instructions.
	Mode string `json:"mode"`
	// SHA256 hashes the complete compiled instructions for Mode.
	SHA256 string `json:"sha256"`
	// Bytes is the compiled instruction size in bytes.
	Bytes int `json:"bytes"`
	// UpstreamIDs lists adapted upstream identities associated with the prompt.
	UpstreamIDs []string `json:"upstream_ids"`
}

// KnowledgeAsset identifies the path, size and digest of an embedded knowledge
// asset.
type KnowledgeAsset struct {
	// Path is the asset path within the embedded knowledge pack.
	Path string `json:"path"`
	// SHA256 hashes the complete asset bytes.
	SHA256 string `json:"sha256"`
	// Bytes is the asset size in bytes.
	Bytes int `json:"bytes"`
}

// KnowledgeManifest identifies the embedded review instructions and guidance
// assets.
type KnowledgeManifest struct {
	// Version identifies the embedded Scout knowledge pack revision.
	Version string `json:"version"`
	// SHA256 hashes the pack version and sorted asset inventory.
	SHA256 string `json:"sha256"`
	// SourceStatus describes provenance and limits of the embedded materials.
	SourceStatus string `json:"source_status"`
	// Prompts identifies the compiled instructions for supported review modes.
	Prompts []PromptDescriptor `json:"prompts"`
	// Assets identifies embedded files and their byte digests.
	Assets []KnowledgeAsset `json:"assets"`
}

// SourceProvenance records acquisition metadata without exposing the original
// or download URL.
type SourceProvenance struct {
	// Kind identifies the remote acquisition form, such as HTTPS bytes or a pinned
	// GitHub archive.
	Kind string `json:"kind"`
	// TargetSHA256 is the SHA-256 digest of the operator-supplied remote target
	// address.
	TargetSHA256 string `json:"target_sha256"`
	// DownloadURLSHA256 is the SHA-256 digest of the resolved download URL.
	DownloadURLSHA256 string `json:"download_url_sha256"`
	// BytesSHA256 is the SHA-256 digest of the complete acquired bytes.
	BytesSHA256 string `json:"bytes_sha256,omitempty"`
	// Revision is the pinned source revision when one applies.
	Revision string `json:"revision,omitempty"`
	// ExpectedChecksumVerified reports whether a caller-supplied checksum matched
	// the acquired bytes.
	ExpectedChecksumVerified bool `json:"expected_checksum_verified"`
	// Bytes is the size of the complete acquired response in bytes.
	Bytes int64 `json:"bytes"`
	// Status records whether remote bytes were captured or acquisition failed.
	Status string `json:"status"`
}

// LanguageHint records a proposed source language and the basis for that hint.
type LanguageHint struct {
	// Language is the proposed source language.
	Language string `json:"language"`
	// Basis identifies the evidence for the language hint, such as an extension or
	// shebang.
	Basis string `json:"basis"`
}

// Classification records format and language hints used to select structural
// analysis.
type Classification struct {
	// Format is the detected file or container format.
	Format string `json:"format"`
	// Category is the file category, such as archive, document, executable or
	// text.
	Category string `json:"category"`
	// Encoding records the detected source encoding.
	Encoding string `json:"encoding"`
	// Basis identifies how Format was selected, such as by extension or file
	// signature.
	Basis string `json:"basis"`
	// Languages lists source-language hints detected for the object.
	Languages []LanguageHint `json:"languages"`
	// Conflict reports conflicting format or language evidence.
	Conflict bool `json:"conflicting_hints"`
	// Executable reports an executable candidate, without claiming that it will
	// run.
	Executable bool `json:"executable_candidate"`
	// Structured reports whether the input requires structural analysis.
	Structured bool `json:"requires_structural_analysis"`
}

// SemanticSettings records review permissions and budgets without provider
// credentials or clients.
type SemanticSettings struct {
	// QualityPolicy selects the separate opt-in quality-policy review stage.
	QualityPolicy bool `json:"quality_policy"`
	// Enabled reports whether this optional operation was explicitly selected.
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
	// Timeout records the per-request timeout; JSON encodes it in nanoseconds.
	Timeout time.Duration `json:"timeout_ns"`
}

// ProviderIdentity records requested provider configuration. It does not prove
// which remote model executed.
type ProviderIdentity struct {
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

// SignatureCapability describes the compiled YARA binding and native backend
// availability.
type SignatureCapability struct {
	// Name identifies the signature engine.
	Name string `json:"name"`
	// BindingVersion records the Go binding revision.
	BindingVersion string `json:"binding_version"`
	// NativeVersion records the native engine version reported by the backend.
	NativeVersion string `json:"native_version"`
	// Available reports whether this build provides the native signature backend.
	Available bool `json:"available"`
	// Reason explains backend unavailability when Available is false.
	Reason string `json:"reason,omitempty"`
}

// SignatureSpan is a zero-based, half-open byte interval in the scanned
// object.
type SignatureSpan struct {
	// Start is the inclusive, zero-based byte offset.
	Start int `json:"start"`
	// End is the exclusive, zero-based byte offset.
	End int `json:"end"`
}

// SignatureMatch records a named signature and the source intervals that
// matched it.
type SignatureMatch struct {
	// Rule names the signature whose condition matched the scanned object.
	Rule string `json:"rule"`
	// Category is the category assigned to the matching signature.
	Category string `json:"category"`
	// Spans records half-open byte intervals associated with the signature match.
	Spans []SignatureSpan `json:"spans"`
	// Severity is assigned by Scout for selected builtins, never by rule metadata.
	Severity Severity `json:"severity,omitempty"`
}

// SignatureOutcome records signature execution for one object, including
// truncation.
type SignatureOutcome struct {
	// Path is the inventory path of the scanned object.
	Path string `json:"path"`
	// SHA256 hashes the complete object bytes passed to YARA-X.
	SHA256 string `json:"sha256"`
	// Status records the signature scan outcome for this object.
	Status string `json:"status"`
	// EngineVersion records the Go binding and native engine versions used for the
	// scan.
	EngineVersion string `json:"engine_version,omitempty"`
	// Matches contains retained signature matches for this object.
	Matches []SignatureMatch `json:"matches"`
	// Truncated reports that output retention omitted matches.
	Truncated bool `json:"truncated"`
}

// SignatureReport records signature engine identity, selected rules and
// per-object execution.
type SignatureReport struct {
	// Enabled records whether YARA-X checks were selected.
	Enabled bool `json:"enabled"`
	// Engine describes the signature backend and its availability.
	Engine SignatureCapability `json:"engine"`
	// RulesSHA256 identifies the selected signature source bytes.
	RulesSHA256 string `json:"rules_sha256,omitempty"`
	// Completeness records whether all selected signature inputs were checked
	// without gaps.
	Completeness string `json:"completeness"`
	// Outcomes contains one execution outcome per planned signature input.
	Outcomes []SignatureOutcome `json:"outcomes"`
	// Limitations lists boundaries of the signature inspection.
	Limitations []string `json:"limitations"`
}
