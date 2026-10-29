// Package report defines passive scan results and their output representations.
package report

import (
	"errors"
)

// Severity classifies finding impact independently of execution completeness
// and policy decisions.
type Severity string

const (
	// Info marks informational findings.
	Info Severity = "info"
	// Low marks findings with low impact.
	Low Severity = "low"
	// Medium marks findings with medium impact.
	Medium Severity = "medium"
	// High marks findings with high impact.
	High Severity = "high"
	// Critical marks findings with critical impact.
	Critical Severity = "critical"
)

// Completeness describes coverage of the selected checks, without claiming
// exhaustive detection.
type Completeness string

const (
	// Complete means the selected scope finished without a recorded coverage gap.
	Complete Completeness = "complete"
	// Partial means some selected scope could not be analyzed.
	Partial Completeness = "partial"
	// Failed means the analysis did not complete successfully.
	Failed Completeness = "failed"
)

// Decision is a trusted policy outcome, separate from finding severity and
// execution state.
type Decision string

const (
	// Allow permits admission under the evaluated policy.
	Allow Decision = "allow"
	// Review requires an operator review under the evaluated policy.
	Review Decision = "review"
	// Block rejects admission under the evaluated policy.
	Block Decision = "block"
)

// Rule describes a check, its detection method and its stated limitations.
type Rule struct {
	// Guidance contains the compiled explanation and review guidance for this
	// check.
	Guidance *Guidance `json:"guidance,omitempty"`
	// ID is the stable check identifier used by findings and guidance.
	ID string `json:"id"`
	// Version identifies the check revision used for occurrence matching.
	Version string `json:"version"`
	// Title is the check's display name.
	Title string `json:"title"`
	// Description describes the behavior the check detects.
	Description string `json:"description"`
	// Severity records the check's default finding severity.
	Severity Severity `json:"severity"`
	// Category classifies the check's security concern.
	Category string `json:"category"`
	// Method identifies the check's detection technique.
	Method string `json:"method"`
	// Limitation states the boundary of the check's detection method.
	Limitation string `json:"limitation"`
}

// Location uses zero-based, half-open original byte offsets. Text locations also
// use one-based Unicode code-point line/column coordinates. Binary locations have
// Coordinates="bytes" and zero line/column values. End coordinates are exclusive.
type Location struct {
	// Derived reports whether the location belongs to an extracted virtual object.
	Derived bool `json:"derived,omitempty"`
	// Path is the inventory path of the object containing the span.
	Path        string `json:"path"`
	Coordinates string `json:"coordinates"` // text or bytes; byte-only locations have no fabricated lines
	// ByteStart is the inclusive, zero-based byte offset in the referenced object.
	ByteStart int `json:"byte_start"`
	// ByteEnd is the exclusive, zero-based byte offset in the referenced object.
	ByteEnd int `json:"byte_end"`
	// StartLine is the one-based start line, or zero for byte-only coordinates.
	StartLine int `json:"start_line"`
	// StartColumn is the one-based Unicode code-point column, or zero for
	// byte-only coordinates.
	StartColumn int `json:"start_column"`
	// EndLine is the one-based exclusive end line, or zero for byte-only
	// coordinates.
	EndLine int `json:"end_line"`
	// EndColumn is the one-based exclusive Unicode code-point column, or zero for
	// byte-only coordinates.
	EndColumn int `json:"end_column"`
	// Context describes the syntactic context of the source location.
	Context string `json:"context"`
	// Structure records the containing structural construct when known.
	Structure string `json:"structure,omitempty"`
	// Language names the selected source language.
	Language string `json:"language,omitempty"`
}

// Evidence identifies a source object and matched span by their SHA-256
// digests, without copying source bytes.
type Evidence struct {
	// FileSHA256 is the SHA-256 digest of the complete captured object.
	FileSHA256 string `json:"file_sha256"`
	// SpanSHA256 is the SHA-256 digest of the selected source bytes.
	SpanSHA256 string `json:"span_sha256"`
}

// Finding records a source-bound security observation. Approvals and model
// assessments do not remove it.
type Finding struct {
	// ContextSignals records context hints for interpretation without lowering
	// severity or granting trust.
	ContextSignals []string `json:"context_signals,omitempty"`
	// SignatureNames lists signature identities contributing to the observation.
	SignatureNames []string `json:"signature_names,omitempty"`
	// RelatedEvidence records additional source spans needed to interpret the
	// observation.
	RelatedEvidence []SourceRef `json:"related_evidence,omitempty"`
	// AdvisoryIDs lists vulnerability database identities associated with the
	// observation.
	AdvisoryIDs []string `json:"advisory_ids,omitempty"`
	// Contexts records plugin and host interpretations without changing the
	// finding's identity.
	Contexts []FindingContext `json:"contexts,omitempty"`
	// ID identifies a source-bound occurrence without collapsing duplicate
	// evidence.
	ID string `json:"id"`
	// RuleID identifies the check that produced the finding.
	RuleID string `json:"rule_id"`
	// RuleVersion identifies the revision of the check that produced the finding.
	RuleVersion string `json:"rule_version"`
	// Severity records the finding's impact independently of execution state or
	// policy.
	Severity Severity `json:"severity"`
	// Category classifies the observed security concern.
	Category string `json:"category"`
	// Method identifies the detection technique that produced the finding.
	Method string `json:"method"`
	// Message contains a bounded explanation without copying source secrets.
	Message string `json:"message"`
	// Location identifies the observed source span in original object coordinates.
	Location Location `json:"location"`
	// Evidence hashes the complete source object and the matched span.
	Evidence Evidence `json:"evidence"`
	// Trace records ordered, source-bound steps that support the observation.
	Trace []TraceStep `json:"trace,omitempty"`
}

// TraceStep binds one step of an observed flow to its original location and
// evidence hashes.
type TraceStep struct {
	// Role identifies the step's contribution to the observed flow.
	Role string `json:"role"`
	// Location identifies the observed source span in original object coordinates.
	Location Location `json:"location"`
	// Evidence hashes the source object and span at this trace step.
	Evidence Evidence `json:"evidence"`
}

// Diagnostic records an analysis condition and whether it leaves a gap in the
// selected scope.
type Diagnostic struct {
	// Code is a stable machine-readable condition identifier.
	Code string `json:"code"`
	// Path identifies the affected inventory object, when the diagnostic is
	// file-specific.
	Path string `json:"path,omitempty"`
	// Message contains a bounded explanation without copying source secrets.
	Message string `json:"message"`
	// AffectsScope reports whether this diagnostic leaves selected work
	// incomplete.
	AffectsScope bool `json:"affects_scope"`
}

// Capture status values record immutable byte acquisition, independently of checks.
const (
	// CaptureCaptured means the object's bytes were retained in the inventory.
	CaptureCaptured = "captured"
	// CaptureAlreadyCaptured means an external reference resolved to retained bytes.
	CaptureAlreadyCaptured = "already_captured"
)

// File describes an inventoried object, including entries whose bytes could
// not be captured.
type File struct {
	// Path is the object's path within the captured inventory.
	Path string `json:"path"`
	// Size is the inventoried object size in bytes.
	Size int64 `json:"size"`
	// SHA256 hashes the complete captured bytes; it is empty when bytes were not
	// captured.
	SHA256 string `json:"sha256,omitempty"`
	// Executable records the inventory's executable flag, without claiming
	// execution.
	Executable bool `json:"executable"`
	// Kind classifies the inventoried entry, including text, binary and unread
	// filesystem objects.
	Kind string `json:"kind"`
	// Status records the entry's capture outcome.
	Status string `json:"status"`
	// Reason explains why an entry was skipped or could not be captured.
	Reason string `json:"reason,omitempty"`
}

// Artifact records the captured inventory and the scope of its snapshot
// identity.
type Artifact struct {
	// SourceKind identifies how the target bytes were acquired.
	SourceKind string `json:"source_kind"`
	// SnapshotSHA256 identifies the captured inventory within IdentityScope.
	SnapshotSHA256 string `json:"snapshot_sha256,omitempty"`
	// InventoryComplete reports whether capture finished inventory traversal
	// within its selected scope.
	InventoryComplete bool `json:"inventory_complete"`
	// IdentityScope states which captured inputs the snapshot digest covers.
	IdentityScope string `json:"identity_scope"`
	// Files contains captured and skipped inventory entries.
	Files []File `json:"files"`
	// Skills lists discovered skill documents within the captured scope.
	Skills []string `json:"skills"`
}

// Check summarizes execution of one analyzer across its selected files.
type Check struct {
	// AnalyzerID identifies the analyzer whose execution is summarized.
	AnalyzerID string `json:"analyzer_id"`
	// Version identifies the analyzer revision used for this execution.
	Version string `json:"version"`
	// Status records the analyzer's aggregate execution outcome.
	Status string `json:"status"`
	// FilesTotal counts files selected for the analyzer.
	FilesTotal int `json:"files_total"`
	// FilesDone counts files on which the analyzer completed.
	FilesDone int `json:"files_done"`
	// Findings counts findings observed by the analyzer.
	Findings int `json:"findings"`
	// Detail contains a bounded explanation of the check outcome.
	Detail string `json:"detail,omitempty"`
}

// Coverage records execution and file coverage for the selected inspection
// plan.
type Coverage struct {
	// AnalyzedObjects counts objects included in analysis.
	AnalyzedObjects int `json:"analyzed_objects"`
	// Completeness records coverage of the selected work, independently of
	// findings and policy.
	Completeness Completeness `json:"completeness"`
	// CapturedFiles counts files whose bytes were captured.
	CapturedFiles int `json:"captured_files"`
	// TextFiles counts captured files classified as text.
	TextFiles int `json:"text_files"`
	// Checks contains aggregate execution outcomes for selected analyzers.
	Checks []Check `json:"checks"`
	// Files contains coverage for each inventoried entry, including unread files.
	Files []FileCoverage `json:"files"`
}

// FileCoverage covers every inventoried entry, including unread or unsupported
// files. complete refers only to the selected profile, not arbitrary behavior.
type FileCoverage struct {
	// Path identifies the inventoried entry covered by this result.
	Path string `json:"path"`
	// ReadStatus records whether the object's bytes were captured.
	ReadStatus string `json:"read_status"`
	// Classification records format and language hints for selecting checks.
	Classification Classification `json:"classification"`
	// Completeness records coverage of the selected work, independently of
	// findings and policy.
	Completeness Completeness `json:"completeness"`
	// Checks contains per-analyzer outcomes for this entry.
	Checks []FileCheck `json:"checks"`
	// Units records parser coverage for source units within the object.
	Units []UnitCoverage `json:"units"`
	// Gaps lists reasons this entry's selected checks are incomplete.
	Gaps []string `json:"gaps"`
}

// FileCheck records one analyzer's execution status for a file.
type FileCheck struct {
	// AnalyzerID identifies the analyzer applied to this entry.
	AnalyzerID string `json:"analyzer_id"`
	// Status records the analyzer's outcome for this entry.
	Status string `json:"status"`
}

// UnitCoverage records parser coverage for a source span within a captured
// object.
type UnitCoverage struct {
	// Language names the selected source language.
	Language string `json:"language"`
	// Origin identifies how the source unit was discovered.
	Origin string `json:"origin"`
	// ParserID identifies the parser used for the source unit.
	ParserID string `json:"parser_id,omitempty"`
	// ParserVersion records the parser revision used for this result.
	ParserVersion string `json:"parser_version,omitempty"`
	// Status records the source unit's parsing outcome.
	Status string `json:"status"`
	// ByteStart is the inclusive, zero-based byte offset in the referenced object.
	ByteStart int `json:"byte_start"`
	// ByteEnd is the exclusive, zero-based byte offset in the referenced object.
	ByteEnd int `json:"byte_end"`
}

// CaptureLimits bounds captured inputs and the finding count recorded with them.
type CaptureLimits struct {
	// MaxEntries bounds inventory entries visited, including entries that cannot
	// be read.
	MaxEntries int `json:"max_entries"`
	// MaxFiles bounds captured files per target.
	MaxFiles int `json:"max_files"`
	// MaxFileBytes bounds the bytes captured from a single file.
	MaxFileBytes int64 `json:"max_file_bytes"`
	// MaxTotalBytes limits captured bytes across one target's files.
	MaxTotalBytes int64 `json:"max_total_bytes"`
	// MaxArchiveBytes bounds the source archive bytes accepted during capture.
	MaxArchiveBytes int64 `json:"max_archive_bytes"`
	// MaxPathBytes bounds the length of an inventoried path in bytes.
	MaxPathBytes int `json:"max_path_bytes"`
	// MaxDepth limits the depth of inventoried paths.
	MaxDepth int `json:"max_depth"`
	// MaxFindings bounds retained findings. Exceeding it leaves an explicit
	// completeness gap.
	MaxFindings int `json:"max_findings"`
}

type budgetRange struct {
	value, min, max int64
	message         string
}

// Analysis contains passive observations for one target. It does not contain
// an installation decision.
type Analysis struct {
	// Inspection records the selected plan and backend availability before execution.
	Inspection InspectionPlan `json:"inspection"`
	// Knowledge identifies the compiled guidance and instruction assets.
	Knowledge KnowledgeManifest `json:"knowledge"`
	// Signatures records native signature identity, selected rules and per-object
	// execution outcomes.
	Signatures SignatureReport `json:"signatures"`
	// Metadata records selected parsed declarations without their raw values.
	Metadata MetadataReport `json:"metadata"`
	// Vulnerabilities records exact-coordinate advisory queries and matches
	// separately from static findings.
	Vulnerabilities VulnerabilityReport `json:"vulnerabilities"`
	// Dependencies contains captured dependency declarations and manifest parsing outcomes.
	Dependencies DependencyReport `json:"dependencies"`
	// Source records remote acquisition provenance when the target was downloaded.
	Source *SourceProvenance `json:"source,omitempty"`
	// External records outcomes of explicitly selected external-reference
	// traversal, when enabled.
	External *ExternalClosure `json:"external,omitempty"`
	// Semantic records model hypotheses, assessments and review completeness
	// separately from static findings.
	Semantic SemanticReport `json:"semantic"`
	// Components contains the interpreted plugin component graph.
	Components ComponentGraph `json:"components"`
	// Validation records the fixed task plan and its execution outcomes.
	Validation ValidationReport `json:"validation"`
	// SchemaVersion identifies the versioned schema used by this contract.
	SchemaVersion string `json:"schema_version"`
	// EngineVersion records the Scout build version used for this analysis.
	EngineVersion string `json:"engine_version"`
	// RulesVersion is retained for reading existing reports. New scans use RulepackDigest.
	RulesVersion string `json:"rules_version,omitempty"`
	// RulepackDigest  selected check configuration and rule data; not an implementation hash.
	RulepackDigest string `json:"rulepack_digest,omitempty"`
	// Profile selected profile name, also recorded in Inspection.
	Profile string `json:"profile"`
	// Artifact records the captured inventory and snapshot scope.
	Artifact Artifact `json:"artifact"`
	// Coverage records aggregate and per-file coverage of the selected checks.
	Coverage Coverage `json:"coverage"`
	// Limits records capture limits and the finding ceiling used for this analysis.
	Limits CaptureLimits `json:"limits"`
	// Extraction records extraction limits, derived objects and skipped children.
	Extraction ExtractionReport `json:"extraction"`
	// AnalysisLimits records fixed implementation ceilings that constrain the
	// available semantics.
	AnalysisLimits AnalysisLimits `json:"analysis_limits"`
	// Rules describes the selected static checks.
	Rules []Rule `json:"rules"`
	// Findings records observations retained in this scope.
	Findings []Finding `json:"findings"`
	// Diagnostics records conditions and gaps encountered during inspection.
	Diagnostics []Diagnostic `json:"diagnostics"`
	// Limitations lists declared boundaries that prevent interpreting the result
	// as exhaustive analysis.
	Limitations []string `json:"limitations"`
}

// AnalysisLimits records fixed implementation ceilings, distinct from the
// configurable input/output limits. Unknown semantics remain partial.
type AnalysisLimits struct {
	// GoFlowOperations bounds operations in the selected Go flow analysis.
	GoFlowOperations int `json:"go_flow_operations"`
	// GoFlowBindings bounds tracked bindings in Go flow analysis.
	GoFlowBindings int `json:"go_flow_bindings"`
	// AgentJSONBytes bounds the bytes in one agent JSON analysis unit.
	AgentJSONBytes int `json:"agent_json_unit_bytes"`
	// AgentJSONNodes bounds visited nodes in agent JSON analysis.
	AgentJSONNodes int `json:"agent_json_nodes"`
	// AgentJSONDepth bounds nested agent JSON traversal depth.
	AgentJSONDepth int `json:"agent_json_depth"`
	// AgentJSONScanBytes bounds bytes considered by agent JSON checks.
	AgentJSONScanBytes int `json:"agent_json_scan_bytes"`
	// ShellUnitBytes bounds one shell analysis unit in bytes.
	ShellUnitBytes int `json:"shell_unit_bytes"`
	// ShellScanBytes bounds bytes considered by shell checks.
	ShellScanBytes int `json:"shell_scan_bytes"`
	// ShellParserDepth bounds shell parser nesting depth.
	ShellParserDepth int `json:"shell_parser_depth"`
	// ShellParserNodes bounds nodes retained by the shell parser.
	ShellParserNodes int `json:"shell_parser_nodes"`
	// ShellOperations bounds operations in shell analysis.
	ShellOperations int `json:"shell_analysis_operations"`
	// ShellBindings bounds tracked shell variable bindings.
	ShellBindings int `json:"shell_bindings"`
	// ShellTraceTransforms bounds transformations retained in a shell evidence trace.
	ShellTraceTransforms int `json:"shell_trace_transforms"`
	// JSONNestingDepth bounds nested JSON extraction depth.
	JSONNestingDepth int `json:"json_extraction_nesting_depth"`
	// UnitsPerFile bounds analysis units discovered in a file.
	UnitsPerFile int `json:"analysis_units_per_file"`
	// EmbeddedUnitBytes bounds the size of one embedded source unit in bytes.
	EmbeddedUnitBytes int `json:"embedded_unit_bytes"`
	// DocumentRegions bounds regions discovered in one document.
	DocumentRegions int `json:"document_regions_per_file"`
	// SourceSegments bounds source-map segments retained for an analysis unit.
	SourceSegments int `json:"source_segments_per_unit"`
	// GoUnitBytes bounds one Go source analysis unit in bytes.
	GoUnitBytes int `json:"go_unit_bytes"`
	// GoScanBytes bounds bytes considered by Go checks.
	GoScanBytes int `json:"go_scan_bytes"`
	// ConstantOperations bounds work used to evaluate supported constant expressions.
	ConstantOperations int `json:"constant_operations"`
	// ConstantStringBytes bounds the bytes retained for one evaluated constant string.
	ConstantStringBytes int `json:"constant_string_bytes"`
}

// Rank returns the severity order from Info through Critical, or -1 for an
// unknown value.
func (s Severity) Rank() int {
	switch s {
	case Info:
		return 0
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	default:
		return -1
	}
}

// DefaultCaptureLimits returns the standard bounded input and finding budgets.
func DefaultCaptureLimits() CaptureLimits {
	return CaptureLimits{
		MaxEntries: 8192, MaxFiles: 4096,
		MaxFileBytes: 1 << 20, MaxTotalBytes: 32 << 20,
		MaxArchiveBytes: 32 << 20, MaxPathBytes: 1024,
		MaxDepth: 32, MaxFindings: 1024,
	}
}

// Validate applies hard ceilings that also bound allocations before per-entry validation.
func (l CaptureLimits) Validate() error {
	return validateBudgets([]budgetRange{
		{value: int64(l.MaxEntries), min: 1, max: 100000, message: "max entries must be in 1..100000"},
		{
			value:   int64(l.MaxFiles),
			min:     1,
			max:     int64(l.MaxEntries),
			message: "max files must be positive and <= max entries",
		},
		{value: l.MaxFileBytes, min: 1, max: 32 << 20, message: "max file bytes must be in 1..33554432"},
		{
			value:   l.MaxTotalBytes,
			min:     l.MaxFileBytes,
			max:     256 << 20,
			message: "max total bytes must be >= max file bytes and <= 268435456",
		},
		{value: l.MaxArchiveBytes, min: 1, max: 128 << 20, message: "max archive bytes must be in 1..134217728"},
		{
			value:   int64(l.MaxPathBytes),
			min:     1,
			max:     4096,
			message: "path budget must be in 1..4096 bytes and depth in 1..128",
		},
		{
			value:   int64(l.MaxDepth),
			min:     1,
			max:     128,
			message: "path budget must be in 1..4096 bytes and depth in 1..128",
		},
		{value: int64(l.MaxFindings), min: 1, max: 100000, message: "max findings must be in 1..100000"},
	})
}

func validateBudgets(budgets []budgetRange) error {
	for _, budget := range budgets {
		if budget.value < budget.min || budget.value > budget.max {
			return errors.New(budget.message)
		}
	}

	return nil
}
