package report

import "errors"

// HarnessOptions is trusted caller configuration, never read from the artifact.
// Host selects an interpretation, not a whitelist of files to scan.
type HarnessOptions struct {
	// Host selects auto, claude-code, codex or agent-skills. The empty value
	// selects auto.
	Host string `json:"host"`
}

// SourceRef identifies immutable bytes without embedding source/secret values.
type SourceRef struct {
	// Path is the inventory path of the object containing the referenced span.
	Path string `json:"path"`
	// SHA256 identifies the complete source object; SpanSHA256 identifies only the
	// selected interval.
	SHA256 string `json:"sha256"`
	// ByteStart is the inclusive, zero-based byte offset in the referenced object.
	ByteStart int `json:"byte_start"`
	// ByteEnd is the exclusive, zero-based byte offset in the referenced object.
	ByteEnd int `json:"byte_end"`
	// SpanSHA256 is the SHA-256 digest of the selected source bytes.
	SpanSHA256 string `json:"span_sha256"`
}

// HarnessLimits records fixed ceilings for plugin interpretation and component
// graph construction.
type HarnessLimits struct {
	// Plugins bounds interpreted plugin roots.
	Plugins int `json:"plugins"`
	// Components bounds retained component declarations.
	Components int `json:"components"`
	// Edges bounds retained component relationships.
	Edges int `json:"edges"`
	// References bounds retained component references.
	References int `json:"references"`
	// Operations bounds work performed while constructing the component graph.
	Operations int `json:"operations"`
}

// PluginInterpretation records how a manifest was interpreted for a host,
// without proving actual host activation.
type PluginInterpretation struct {
	// ID identifies the interpreted plugin root and host context.
	ID string `json:"id"`
	// Host identifies the host whose manifest contract was used.
	Host string `json:"host"`
	// Namespace records the interpreted plugin namespace used to group related
	// declarations.
	Namespace string `json:"namespace"`
	// Root names the interpreted plugin root in the captured inventory.
	Root string `json:"root"`
	// Manifests lists captured manifest paths used for this plugin interpretation.
	Manifests []string `json:"manifests"`
	// AdapterID identifies the selected host interpretation adapter.
	AdapterID string `json:"adapter_id"`
	// AdapterVersion records the interpretation adapter revision.
	AdapterVersion string `json:"adapter_version"`
	// Contract identifies the host interpretation contract.
	Contract string `json:"contract"`
	// FormatStatus records manifest format validity separately from security
	// findings.
	FormatStatus string `json:"format_status"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
	// Assumptions lists interpretation assumptions that remain visible to the
	// operator.
	Assumptions []string `json:"assumptions"`
}

// Component records a source-bound plugin declaration and its inferred
// activation context.
type Component struct {
	// ID identifies a source-bound component within the captured graph.
	ID string `json:"id"`
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id,omitempty"`
	// Kind classifies a declaration such as a skill, hook or tool.
	Kind string `json:"kind"`
	// Path is the component's inventory path, when it has a local source object.
	Path string `json:"path,omitempty"`
	// PackagePath records the component's package-relative location.
	PackagePath string `json:"package_path,omitempty"`
	// Host identifies the host interpretation used for the declaration.
	Host string `json:"host"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
	// Source binds the declaration to its captured source span when available.
	Source *SourceRef `json:"source,omitempty"`
}

// ComponentEdge records a declared or inferred relationship between two
// components.
type ComponentEdge struct {
	// ID identifies a relationship in the component graph.
	ID string `json:"id"`
	// From identifies the source component of the relationship.
	From string `json:"from"`
	// To identifies the destination component of the relationship.
	To string `json:"to"`
	// Relation identifies how From relates to To.
	Relation string `json:"relation"`
	// Basis records the declaration or inference used to establish the
	// relationship.
	Basis string `json:"basis"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
	// Source binds the relationship to its declaration when available.
	Source *SourceRef `json:"source,omitempty"`
}

// ComponentReference never exposes the raw command, URL or environment placeholder.
// A resolved file does not prove that its command is reachable or will execute.
type ComponentReference struct {
	// ID identifies a reference whose resolution outcome is recorded separately.
	ID string `json:"id"`
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id"`
	// ComponentID identifies the component containing the reference.
	ComponentID string `json:"component_id"`
	// Kind classifies the selected command, path or external reference.
	Kind string `json:"kind"`
	// Status records the reference-resolution outcome.
	Status string `json:"status"`
	// Reason records the bounded reason for the outcome.
	Reason string `json:"reason"`
	// TargetID identifies the resolved component when resolution succeeds.
	TargetID string `json:"target_id,omitempty"`
	// Source binds the reference declaration to its captured source span.
	Source *SourceRef `json:"source,omitempty"`
}

// HarnessIssue records a manifest interpretation gap without exposing raw
// command or environment values.
type HarnessIssue struct {
	// Code is a stable machine-readable condition identifier.
	Code string `json:"code"`
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id,omitempty"`
	// Path identifies the manifest or source object affected by the interpretation
	// gap.
	Path string `json:"path,omitempty"`
	// Status records the interpretation outcome associated with Code.
	Status string `json:"status"`
}

// ComponentGraph records bounded plugin interpretation, components,
// relationships and unresolved references.
type ComponentGraph struct {
	// RequestedHost records the operator-selected host interpretation.
	RequestedHost string `json:"requested_host"`
	// FormatScope states the scope of manifest format interpretation.
	FormatScope string `json:"format_scope"`
	// Limits records fixed ceilings for graph construction.
	Limits HarnessLimits `json:"limits"`
	// Plugins records bounded host interpretations of discovered plugin roots.
	Plugins []PluginInterpretation `json:"plugins"`
	// Components records source-bound declarations in the captured plugin graph.
	Components []Component `json:"components"`
	// Edges records declared and inferred relationships between graph components.
	Edges []ComponentEdge `json:"edges"`
	// References records resolved and unresolved references independently of
	// component declarations.
	References []ComponentReference `json:"references"`
	// Issues contains manifest interpretation and reference-resolution gaps.
	Issues []HarnessIssue `json:"issues"`
}

// FindingContext enriches interpretation but never changes evidence, ID or severity.
type FindingContext struct {
	// ComponentID identifies the component associated with the finding.
	ComponentID string `json:"component_id"`
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id,omitempty"`
	// Host identifies the host interpretation used for this finding context.
	Host string `json:"host"`
	// Relation describes how the finding relates to the component.
	Relation string `json:"relation"`
	// Activation records inferred activation without proving that a host will
	// execute the component.
	Activation string `json:"activation"`
}

// AnalysisTask is fixed after discovery and BEFORE security checks run.
// Capture/extraction/preparation have their own ledgers; they are not retroactively
// claimed to have been scheduled by this plan.
type AnalysisTask struct {
	// PluginID identifies the containing plugin interpretation.
	PluginID string `json:"plugin_id,omitempty"`
	// ReferenceID identifies the component reference selected for analysis.
	ReferenceID string `json:"reference_id,omitempty"`
	// ID identifies the planned task for matching exactly one execution outcome.
	ID string `json:"id"`
	// Kind classifies the work selected by the validation plan.
	Kind string `json:"kind"`
	// AnalyzerID identifies the analyzer scheduled by this task, when applicable.
	AnalyzerID string `json:"analyzer_id,omitempty"`
	// Version records the selected task implementation or analyzer revision.
	Version string `json:"version"`
	// Path is the inventory path selected as task input, when applicable.
	Path string `json:"path,omitempty"`
	// InputSHA256 identifies the selected source bytes, or the sorted input
	// inventory for an analyzer task covering every prepared file.
	InputSHA256 string `json:"input_sha256,omitempty"`
	// ComponentID identifies the component selected for this task, when
	// applicable.
	ComponentID string `json:"component_id,omitempty"`
	// Required reports whether this task must complete for validation to be
	// complete.
	Required bool `json:"required"`
}

// TaskOutcome records completion or a gap for one previously planned analysis
// task.
type TaskOutcome struct {
	// TaskID identifies the planned task associated with this result.
	TaskID string `json:"task_id"`
	// Status records the planned task's execution outcome.
	Status string `json:"status"`
	// Reason records the bounded reason for the outcome.
	Reason string `json:"reason"`
}

// ValidationReport binds a fixed task plan to its outcomes and records omitted
// or unfinished work.
type ValidationReport struct {
	// Scope describes the analysis phase covered by the task ledger.
	Scope string `json:"scope"`
	// PlanSHA256 binds the task plan independently of its execution outcomes.
	PlanSHA256 string `json:"plan_sha256"`
	// MaxTasks bounds the retained analysis task plan.
	MaxTasks int `json:"max_tasks"`
	// OmittedTasks counts tasks excluded by the planning limit.
	OmittedTasks int `json:"omitted_tasks"`
	// Tasks contains tasks fixed before their analysis phase executes.
	Tasks []AnalysisTask `json:"tasks"`
	// Outcomes contains execution outcomes keyed by task ID.
	Outcomes []TaskOutcome `json:"outcomes"`
	// Completeness records coverage of the selected work, independently of
	// findings and policy.
	Completeness Completeness `json:"completeness"`
	// Issues lists missing, failed or otherwise incomplete validation work.
	Issues []string `json:"issues"`
}

// Validate rejects unsupported host names. An empty host selects automatic
// interpretation.
func (o HarnessOptions) Validate() error {
	switch o.Host {
	case "", HostAuto, HostClaudeCode, HostCodex, HostAgentSkills:
		return nil
	default:
		return errors.New("harness must be auto, claude-code, codex or agent-skills")
	}
}
