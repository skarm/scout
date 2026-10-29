package report

// MetadataField records a selected declaration through hashes and source
// coordinates, without its raw value.
type MetadataField struct {
	// Name is the selected declaration's field name.
	Name string `json:"name"`
	// ValueSHA256 identifies a declaration's value without exposing its raw text.
	ValueSHA256 string `json:"value_sha256"`
	// Kind records the parsed declaration's value shape.
	Kind string `json:"kind"`
	// Source binds the selected declaration to its captured source span.
	Source SourceRef `json:"source"`
	// Items records hashed members of a selected declaration.
	Items []MetadataItem `json:"items,omitempty"`
	// ItemsComplete reports whether all selected members were inventoried.
	ItemsComplete bool `json:"items_complete,omitempty"`
}

// MetadataItem holds hashed declarations for update comparison without leaking parameter
// defaults, permission text, descriptions or trigger phrases into reports.
type MetadataItem struct {
	// NameSHA256 identifies a declaration name without exposing its raw text.
	NameSHA256 string `json:"name_sha256"`
	// ValueSHA256 identifies a declaration's value without exposing its raw text.
	ValueSHA256 string `json:"value_sha256"`
}

// MetadataFile records parsed metadata and issues for one captured file.
type MetadataFile struct {
	// Path is the inventory path of the metadata source file.
	Path string `json:"path"`
	// Format identifies the parsed configuration format or frontmatter.
	Format string `json:"format"`
	// Status records the metadata parsing outcome.
	Status string `json:"status"`
	// Parser identifies the parser used to extract these declarations.
	Parser string `json:"parser"`
	// ParserVersion records the parser revision used for this result.
	ParserVersion string `json:"parser_version"`
	// Fields records selected source-bound declarations.
	Fields []MetadataField `json:"fields"`
	// Issues lists gaps in metadata parsing or declaration inventory.
	Issues []string `json:"issues"`
}

// MetadataReport records selected metadata declarations and their coverage
// limitations.
type MetadataReport struct {
	// Files contains metadata extraction results for the selected files.
	Files []MetadataFile `json:"files"`
	// Completeness records whether selected metadata was inventoried without gaps.
	Completeness Completeness `json:"completeness"`
	// Limitations lists unsupported metadata semantics and extraction boundaries.
	Limitations []string `json:"limitations"`
}
