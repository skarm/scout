package report

// ExtractionLimits bounds one extraction pass across its input roots and
// recursion levels. Scanner applies these limits per target, with a separate
// run-wide extracted-byte budget.
type ExtractionLimits struct {
	// MaxDepth limits recursive extraction depth from an input root.
	MaxDepth int `json:"max_depth"`
	// MaxObjects bounds retained derived objects across extraction.
	MaxObjects int `json:"max_objects"`
	// MaxEntries limits visited container entries, including rejected members.
	MaxEntries int `json:"max_entries"`
	// MaxObjectBytes bounds bytes produced for a single derived object.
	MaxObjectBytes int64 `json:"max_object_bytes"`
	// MaxTotalBytes limits output bytes across the extraction pass, including
	// failed output reads.
	MaxTotalBytes int64 `json:"max_total_bytes"`
}

// DerivedObject describes an in-memory child extracted from a captured object.
// Finding offsets refer to File, not the encoded parent. ParentRange encloses
// the source representation without implying a byte-for-byte mapping.
type DerivedObject struct {
	Role string `json:"role"` // archive_member, metadata or decoded; not a trust label
	// ID distinguishes this child occurrence by its parent and extraction
	// identity.
	ID string `json:"id"`
	// File describes the child's own virtual bytes and inventory identity.
	File File `json:"file"`
	// ParentPath names the source object from which a child was derived.
	ParentPath string `json:"parent_path"`
	// ParentSHA256 identifies the captured parent bytes.
	ParentSHA256 string `json:"parent_sha256"`
	// ExtractorID identifies the extractor that produced this child.
	ExtractorID string `json:"extractor_id"`
	// ExtractorVersion identifies the extractor revision.
	ExtractorVersion string `json:"extractor_version"`
	// Depth is the child's extraction depth from an input root.
	Depth int `json:"depth"`
	// Ordinal distinguishes repeated child occurrences within the parent.
	Ordinal int `json:"ordinal"`
	// MemberName retains the container member name when available.
	MemberName string `json:"member_name,omitempty"`
	// ParentRange encloses the encoded source representation when known; it is not
	// a byte-for-byte mapping.
	ParentRange *ByteRange `json:"parent_range,omitempty"`
	// CoordinateSpace identifies the object's own byte coordinate space.
	CoordinateSpace string `json:"coordinate_space"`
}

// ByteRange is a zero-based, half-open byte interval.
type ByteRange struct {
	// Start is the inclusive, zero-based byte offset.
	Start int `json:"start"`
	// End is the exclusive, zero-based byte offset.
	End int `json:"end"`
}

// ExtractionStep records one extractor's attempt to produce children from an
// object.
type ExtractionStep struct {
	// ParentPath is the inventory path of the object given to the extractor.
	ParentPath string `json:"parent_path"`
	// ExtractorID identifies the extractor that attempted this step.
	ExtractorID string `json:"extractor_id"`
	// Version identifies the extractor revision used for this attempt.
	Version string `json:"version"`
	// Status records the outcome of this extraction attempt.
	Status string `json:"status"`
	// Objects counts children produced by the extractor attempt.
	Objects int `json:"objects"`
}

// SkippedObject records a known child whose complete validated bytes were not
// obtained. It has no fabricated hash, source coordinates, or analysis result.
type SkippedObject struct {
	// Role describes this object's role in the enclosing operation.
	Role string `json:"role"`
	// ParentPath names the source object from which a child was derived.
	ParentPath string `json:"parent_path"`
	// ExtractorID identifies the extractor that encountered the skipped child.
	ExtractorID string `json:"extractor_id"`
	// MemberName retains the container member name when available.
	MemberName string `json:"member_name"`
	// Ordinal distinguishes repeated child occurrences within the parent.
	Ordinal      int   `json:"ordinal"`
	DeclaredSize int64 `json:"declared_size"` // -1 means unknown
	// Reason records the bounded reason for the outcome.
	Reason string `json:"reason"`
}

// ExtractionReport records bounded extraction, including produced and skipped
// children.
type ExtractionReport struct {
	// Skipped records known children whose complete validated bytes were not
	// obtained.
	Skipped []SkippedObject `json:"skipped"`
	// Limits records the applicable resource ceilings.
	Limits ExtractionLimits `json:"limits"`
	// Skills lists discovered skill documents within the captured scope.
	Skills []string `json:"skills"`
	// Objects records produced virtual children without replacing their original
	// containers.
	Objects []DerivedObject `json:"objects"`
	// Steps records extractor attempts independently of produced or skipped
	// children.
	Steps []ExtractionStep `json:"steps"`
	// EntriesVisited counts extraction entries visited, including entries that do
	// not produce an object.
	EntriesVisited int `json:"entries_visited"`
	// BytesProduced counts extraction output bytes charged to the shared budget.
	BytesProduced int64 `json:"bytes_produced"`
}

// DefaultExtractionLimits returns default limits for one extraction pass.
func DefaultExtractionLimits() ExtractionLimits {
	return ExtractionLimits{
		MaxDepth:       4,
		MaxObjects:     256,
		MaxEntries:     8192,
		MaxObjectBytes: 1 << 20,
		MaxTotalBytes:  16 << 20,
	}
}

// Validate rejects nonpositive limits, values above hard ceilings and a total
// byte limit below the per-object limit.
func (l ExtractionLimits) Validate() error {
	return validateBudgets([]budgetRange{
		{value: int64(l.MaxDepth), min: 1, max: 16, message: "extraction depth must be in 1..16"},
		{value: int64(l.MaxObjects), min: 1, max: 4096, message: "extraction objects must be in 1..4096"},
		{value: int64(l.MaxEntries), min: 1, max: 100000, message: "extraction entries must be in 1..100000"},
		{value: l.MaxObjectBytes, min: 1, max: 32 << 20, message: "extraction object bytes must be in 1..33554432"},
		{
			value:   l.MaxTotalBytes,
			min:     l.MaxObjectBytes,
			max:     128 << 20,
			message: "extraction total bytes must be >= object bytes and <= 134217728",
		},
	})
}
