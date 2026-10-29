package report

// Dependency describes a declaration, NOT a resolved build graph. In go.mod a
// require version is a minimum under MVS; no installed version is inferred.
type Dependency struct {
	// ID identifies this declaration for advisory queries and update comparison.
	ID string `json:"id"`
	// Ecosystem identifies the package ecosystem used for exact-coordinate
	// advisory lookup.
	Ecosystem string `json:"ecosystem"`
	// Module is the package or module name as declared in the manifest.
	Module string `json:"module"`
	// DeclaredVersion retains the version expression as declared, without
	// inferring an installed version.
	DeclaredVersion string `json:"declared_version"`
	// VersionSemantics states how to interpret the declared version expression.
	VersionSemantics string `json:"version_semantics"`
	// Indirect reports an explicit indirect dependency declaration.
	Indirect bool `json:"indirect"`
	// Replacement classifies a declared dependency replacement.
	Replacement string `json:"replacement"`
	// ReplacementModule names the replacement module when declared.
	ReplacementModule string `json:"replacement_module,omitempty"`
	// ReplacementVersion retains the declared replacement version when present.
	ReplacementVersion string `json:"replacement_version,omitempty"`
	// Source binds the declaration to its captured manifest bytes and source span.
	Source SourceRef `json:"source"`
	// ReplacementSource identifies the replacement declaration's source span.
	ReplacementSource *SourceRef `json:"replacement_source,omitempty"`
}

// DependencyManifest records the parser and declaration inventory status for
// one manifest.
type DependencyManifest struct {
	// Path is the captured manifest's inventory path.
	Path string `json:"path"`
	// Status records whether declaration inventory completed, was limited or
	// failed.
	Status string `json:"status"`
	// Parser identifies the manifest parser.
	Parser string `json:"parser"`
	// ParserVersion records the parser revision used for this result.
	ParserVersion string `json:"parser_version"`
}

// DependencyReport records declared dependencies, without resolving a build or
// installation graph.
type DependencyReport struct {
	// Scope describes the captured declaration inventory covered by this report.
	Scope string `json:"scope"`
	// Manifests records parser identity and inventory status for each selected
	// manifest.
	Manifests []DependencyManifest `json:"manifests"`
	// Declarations records captured dependency declarations.
	Declarations []Dependency `json:"declarations"`
	// Limitations lists declared boundaries that prevent interpreting the result
	// as exhaustive analysis.
	Limitations []string `json:"limitations"`
}

// InventoryComplete reports whether the manifest's supported declaration
// inventory finished. It does not attest installation or complete ecosystem semantics.
func (m DependencyManifest) InventoryComplete() bool {
	switch m.Status {
	case OutcomeCompleted, UnitParsedLimited:
		return true
	default:
		return false
	}
}
