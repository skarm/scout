package environment

import "github.com/skarm/scout/report"

// Surface is the passive input to an explicitly selected environment analysis.
// Collectors supply source-bound facts without exposing their parser or flow
// implementation. Scalar values are for internal use and belong to one scan.
type Surface struct {
	IncludeCapabilityDetails bool
	Complete                 bool
	Limited                  bool
	Facts                    []SurfaceFact
	UnknownSkillDescriptions int
}

// SurfaceFact is a syntactic observation, not an assertion of activation or flow.
type SurfaceFact struct {
	Kind, Value, Scope string
	Source             report.SourceRef
	Line               int
}
