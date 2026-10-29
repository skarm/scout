package report

// ExternalClosure describes an explicitly selected bounded traversal. Complete
// means the literal references selected by this traversal were captured; it is
// never a guarantee about arbitrary package-manager or runtime installations.
type ExternalClosure struct {
	// Complete reports completion only within the explicitly selected traversal scope.
	Complete bool `json:"complete"`
	// MaxDepth limits recursive external-reference traversal from the original target.
	MaxDepth int `json:"max_depth"`
	// MaxRequests limits attempted external downloads.
	MaxRequests int `json:"max_requests"`
	// MaxBytes limits the traversal's aggregate download byte budget.
	MaxBytes int64 `json:"max_bytes"`
	// References records outcomes for selected literal external references.
	References []ExternalReference `json:"references"`
}

// ExternalReference records capture status and hashes for one selected literal
// external reference.
type ExternalReference struct {
	// Source binds the literal URL declaration to the captured source span.
	Source SourceRef `json:"source"`
	// URLSHA256 identifies a referenced URL without exposing its text.
	URLSHA256 string `json:"url_sha256"`
	// Path is the captured external object's inventory path, when acquisition succeeded.
	Path string `json:"path,omitempty"`
	// BytesSHA256 is the SHA-256 digest of the complete acquired bytes.
	BytesSHA256 string `json:"bytes_sha256,omitempty"`
	// Depth is the number of reference hops from the original target.
	Depth int `json:"depth"`
	// Status records the external capture outcome, including denials, limits and
	// download failures.
	Status string `json:"status"`
}
