package report

// Suppression is an operator decision, not deletion of a security observation.
type Suppression struct {
	// TargetID is empty in per-analysis baseline results and set by the Gate for
	// a Run. Prepare resolves unique legacy occurrences and rejects ambiguity.
	TargetID string `json:"target_id,omitempty"`
	// FindingID identifies the finding exempted by the operator approval.
	FindingID string `json:"finding_id"`
	// EntryIndex is the zero-based index of the matching baseline entry.
	EntryIndex int `json:"entry_index"`
	// Kind records whether the operator approval used a fingerprint or a glob selector.
	Kind string `json:"kind"`
	// ReasonSHA256 identifies the operator's approval reason without exposing its raw text.
	ReasonSHA256 string `json:"reason_sha256"`
	// Expires is the exclusive RFC3339 approval expiry time.
	Expires string `json:"expires"`
}

// Vulnerability records a database advisory associated with captured exact
// dependency coordinates.
type Vulnerability struct {
	// ID is the advisory identifier returned by the database.
	ID string `json:"id"`
	// DependencyIDs lists the captured dependency declarations associated with the advisory.
	DependencyIDs []string `json:"dependency_ids"`
	// Aliases lists alternate advisory identifiers reported by the database.
	Aliases []string `json:"aliases,omitempty"`
	// DatabaseModified records the advisory modification time reported by the database.
	DatabaseModified string `json:"database_modified,omitempty"`
}

// VulnerabilityQuery records whether an exact captured dependency coordinate
// was checked.
type VulnerabilityQuery struct {
	// DependencyID identifies the captured dependency declaration being queried.
	DependencyID string `json:"dependency_id"`
	// Ecosystem identifies the package ecosystem used for exact-coordinate
	// advisory lookup.
	Ecosystem string `json:"ecosystem"`
	// Name is the captured package name used for the exact-coordinate query.
	Name string `json:"name"`
	// Version is an exact captured package version, not a dependency range.
	Version string `json:"version"`
	// Status records whether this dependency's advisory query completed, used a
	// cache or left a gap.
	Status string `json:"status"`
}

// VulnerabilityReport records advisory queries, matches and limitations for
// the selected source.
type VulnerabilityReport struct {
	// Enabled records whether advisory lookup was selected.
	Enabled bool `json:"enabled"`
	// Source identifies the explicit offline-cache or network advisory source.
	Source string `json:"source"`
	// DatabaseSHA256 identifies the supplied offline advisory cache bytes.
	DatabaseSHA256 string `json:"database_sha256,omitempty"`
	// QueriedAt records the oldest trusted query time among included advisory
	// sources, so exporting mixed network/cache results cannot renew cached data.
	QueriedAt string `json:"queried_at,omitempty"`
	// Completeness records coverage of the selected dependency queries.
	Completeness Completeness `json:"completeness"`
	// Queries records exact-coordinate query outcomes.
	Queries []VulnerabilityQuery `json:"queries"`
	// Matches contains advisory records associated with the queried dependencies.
	Matches []Vulnerability `json:"matches"`
	// Limitations lists boundaries of the advisory lookup.
	Limitations []string `json:"limitations"`
}
