package environment

import "github.com/skarm/scout/report"

// Surface is the passive input to an explicitly selected environment analysis.
// Collectors supply source-bound facts without exposing their parser or flow
// implementation. It contains no source bodies and belongs to one scan.
type Surface struct {
	Complete bool
	Limited  bool
	Facts    []SurfaceFact
}

// SurfaceFact is a syntactic observation, not an assertion of activation or flow.
type SurfaceFact struct {
	Kind, Value, Scope string
	Source             report.SourceRef
}
