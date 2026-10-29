package report

import "errors"

// UpdateOptions limits retained deltas, independently of each scan's input limits.
// The update workflow always rescans both local targets using one Scanner config.
type UpdateOptions struct {
	// MaxChanges bounds retained comparison changes. Omitted changes leave the
	// comparison incomplete.
	MaxChanges int `json:"max_changes"`
}

// ObjectAddress identifies corresponding captured objects without content hashes.
// Archive members use names, not ZIP order. Non-member transforms use ordinals:
// changes to their ordering are conservative deltas, not guessed semantic matches.
// SingleFile is used ONLY when both operator-selected targets are standalone files.
type ObjectAddress struct {
	// SingleFile reports that both compared roots are standalone files, enabling
	// root-name-independent matching.
	SingleFile bool `json:"single_file,omitempty"`
	// Root identifies the root object within the selected input.
	Root string `json:"root,omitempty"`
	// Steps identifies the ordered extraction path from Root to the corresponding
	// object.
	Steps []ObjectStep `json:"steps,omitempty"`
}

// ObjectStep identifies one extraction step in a content-independent object
// address.
type ObjectStep struct {
	// Role identifies the extraction role within the object's address.
	Role string `json:"role"`
	// Extractor names the extractor in a content-independent object address.
	Extractor string `json:"extractor"`
	// ExtractorVersion identifies the extractor revision.
	ExtractorVersion string `json:"extractor_version"`
	// Member identifies an archive member by name rather than archive order.
	Member string `json:"member,omitempty"`
	// Ordinal distinguishes repeated child occurrences within the parent.
	Ordinal int `json:"ordinal,omitempty"`
}

// FileChange compares an object's inventory records without treating
// unavailable bytes as equal.
type FileChange struct {
	// ObjectID identifies the corresponding original or derived object on both
	// sides.
	ObjectID string `json:"object_id"`
	// Address identifies the corresponding object without using content hashes.
	Address ObjectAddress `json:"address"`
	Change  string        `json:"change"` // added, removed, modified, renamed_input, unverified
	// Reasons lists the observed causes of the file change classification.
	Reasons []string `json:"reasons"`
	// Before contains the prior inventory record, or nil when no prior object
	// exists.
	Before *File `json:"before,omitempty"`
	// After contains the candidate inventory record, or nil when no candidate
	// object exists.
	After *File `json:"after,omitempty"`
}

// ComponentChange compares multisets, not arbitrary one-to-one identities for
// unnamed hooks. IDs resolve to the corresponding before/after component graphs.
type ComponentChange struct {
	// GroupID identifies a comparison group whose members are compared as a
	// multiset.
	GroupID string `json:"group_id"`
	// ObjectID identifies the captured object containing the component group.
	ObjectID string `json:"object_id,omitempty"`
	// Kind is the component kind shared by the comparison group.
	Kind string `json:"kind"`
	// Host identifies the host interpretation used for the group.
	Host string `json:"host"`
	// Change classifies the observed difference without asserting remediation or
	// execution.
	Change string `json:"change"`
	// BeforeIDs lists corresponding identities in the prior component graph.
	BeforeIDs []string `json:"before_ids"`
	// AfterIDs lists corresponding identities in the candidate component graph.
	AfterIDs []string `json:"after_ids"`
	// NotMatchedBefore lists prior-side components without an equal candidate-side
	// occurrence.
	NotMatchedBefore []string `json:"not_matched_before"`
	// NotMatchedAfter lists candidate-side components without an equal prior-side
	// occurrence.
	NotMatchedAfter []string `json:"not_matched_after"`
	// Matched counts equal component occurrences matched across the two sides.
	Matched int `json:"matched"`
}

// DependencyChange compares declaration groups without inferring installed
// dependency versions.
type DependencyChange struct {
	// GroupID identifies a comparison group whose members are compared as a
	// multiset.
	GroupID string `json:"group_id"`
	// ObjectID identifies the captured manifest containing the declaration group.
	ObjectID string `json:"object_id"`
	// Change classifies the observed difference without asserting remediation or
	// execution.
	Change string `json:"change"`
	// Before contains the prior side's dependency declarations in this group.
	Before []Dependency `json:"before"`
	// After contains the candidate side's dependency declarations in this group.
	After []Dependency `json:"after"`
}

// FindingChange never removes findings from either report. not_observed is NOT
// a claim of remediation; unverified means the relevant candidate check did not
// complete or the containing object was unavailable.
type FindingChange struct {
	// ObjectID identifies the corresponding source object for this finding change.
	ObjectID string `json:"object_id"`
	Change   string `json:"change"` // introduced, not_observed, unverified, relocated, context_changed
	// RuleID identifies the check whose observations are being compared.
	RuleID string `json:"rule_id"`
	// BeforeID identifies the corresponding prior-side finding when observed.
	BeforeID string `json:"before_id,omitempty"`
	// AfterID identifies the corresponding candidate-side finding when observed.
	AfterID string `json:"after_id,omitempty"`
	// BeforeLocation records the prior-side source location when available.
	BeforeLocation *Location `json:"before_location,omitempty"`
	// AfterLocation records the candidate-side source location when available.
	AfterLocation *Location `json:"after_location,omitempty"`
}

// UpdateCounts summarizes comparison observations, including changes omitted
// by retention limits.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type UpdateCounts struct {
	// ManifestSignals counts retained security-relevant declaration changes.
	ManifestSignals int `json:"manifest_signals"`
	// FileChanges counts observed file changes, including those omitted by
	// retention limits.
	FileChanges int `json:"file_changes"`
	// UnchangedObjects counts corresponding objects with equal observed content.
	UnchangedObjects int `json:"unchanged_objects"`
	// ComponentChanges counts changed component groups, including omitted groups.
	ComponentChanges int `json:"component_changes"`
	// DependencyChanges counts changed dependency groups, including omitted
	// groups.
	DependencyChanges int `json:"dependency_changes"`
	// FindingChanges counts observed finding changes, including omitted changes.
	FindingChanges int `json:"finding_changes"`
	// PersistentFindings counts findings observed on both sides.
	PersistentFindings int `json:"persistent_findings"`
	// IntroducedFindings counts candidate findings whose absence in the prior
	// version was checked.
	IntroducedFindings int `json:"introduced_findings"`
	// UnobservedFindings counts prior-side findings not observed in the candidate;
	// this does not prove remediation.
	UnobservedFindings int `json:"unobserved_findings"`
}

// UpdateDelta compares two fresh scans while retaining each side's full
// findings separately.
type UpdateDelta struct {
	// ManifestSignals records selected security-relevant declaration changes
	// between the two scans.
	ManifestSignals []ManifestSignal `json:"manifest_signals"`
	// AlgorithmVersion identifies the comparison algorithm used for this delta.
	AlgorithmVersion string `json:"algorithm_version"`
	// Completeness records coverage of the selected work, independently of
	// findings and policy.
	Completeness Completeness `json:"completeness"`
	// SameSnapshot reports equality of the compared captured snapshot identities.
	SameSnapshot bool `json:"same_snapshot"`
	// Counts summarizes comparison observations before change retention limits.
	Counts UpdateCounts `json:"counts"`
	// Files contains retained file changes.
	Files []FileChange `json:"files"`
	// Components records changes to component multisets without guessing
	// identities for unnamed hooks.
	Components []ComponentChange `json:"components"`
	// Dependencies records changes to observed dependency declarations without
	// resolving installed packages.
	Dependencies []DependencyChange `json:"dependencies"`
	// Findings contains retained differences between the two sides' findings.
	Findings []FindingChange `json:"findings"`
	// OmittedChanges counts changes omitted by retention limits.
	OmittedChanges int `json:"omitted_changes"`
	// Issues lists gaps that prevent a complete comparison.
	Issues []string `json:"issues"`
}

// ManifestSignal records a source-bound change to a security-relevant manifest
// field.
type ManifestSignal struct {
	// RuleID identifies the manifest-change check that produced this signal.
	RuleID string `json:"rule_id"`
	// Severity is the impact assigned to the declaration change.
	Severity Severity `json:"severity"`
	// Field identifies the manifest field associated with a change signal.
	Field string `json:"field"`
	// Change classifies the observed difference without asserting remediation or
	// execution.
	Change string `json:"change"`
	// Before locates the prior declaration, when present.
	Before *SourceRef `json:"before,omitempty"`
	// After locates the candidate declaration, when present.
	After *SourceRef `json:"after,omitempty"`
}

// DefaultUpdateOptions returns the standard ceiling for retained update
// changes.
func DefaultUpdateOptions() UpdateOptions { return UpdateOptions{MaxChanges: 4096} }

// Validate checks that MaxChanges is within the supported range of 1 through
// 20000.
func (o UpdateOptions) Validate() error {
	if o.MaxChanges < 1 || o.MaxChanges > 20000 {
		return errors.New("max update changes must be in 1..20000")
	}

	return nil
}
