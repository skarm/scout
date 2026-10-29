package report

const (
	// UnitParsedLimited means the parser finished within its documented syntax scope.
	// It does not claim exhaustive language semantics.
	UnitParsedLimited = "parsed_limited"
	// UnitParseError means the selected input did not satisfy the parser grammar.
	UnitParseError = "parse_error"
)

// InspectionPlan describes selection and compiled availability before execution.
// Outcomes and completeness remain in Coverage/Validation; availability is not
// evidence that a selected check completed or that its detection is exhaustive.
type InspectionPlan struct {
	// Scope describes the checks and language semantics covered by the plan.
	Scope string `json:"scope"`
	// Name is the resolved plan name after explicit profile selection.
	Name string `json:"name"`
	// RequestedProfile retains the profile name supplied by the caller when
	// available.
	RequestedProfile string `json:"requested_profile,omitempty"`
	// Checks records check selection and backend availability before execution.
	Checks []InspectionCheck `json:"checks"`
	// Egress records explicit outbound data-transfer permissions.
	Egress InspectionEgress `json:"egress"`
	// Requirements lists prerequisites for the selected checks.
	Requirements []string `json:"requirements"`
	// Limits records the applicable resource ceilings.
	Limits *ExecutionLimits `json:"limits,omitempty"`
}

// ExecutionLimits records units and scope without service credentials or runtime
// objects. Duration fields are nanoseconds. Capture limits are per target;
// aggregate limits and retention apply to the whole run.
type ExecutionLimits struct {
	// Capture records capture limits applied separately to each target.
	Capture CaptureLimits `json:"capture_per_target"`
	// Extraction records extraction limits applied separately to each target.
	Extraction ExtractionLimits `json:"extraction_per_target"`
	// MaxOperations records the run's analysis work budget, divided among targets
	// and tasks.
	MaxOperations uint64 `json:"max_operations"`
	// MaxMatchesPerRule records the match ceiling per analyzer across one target's
	// files.
	MaxMatchesPerRule int `json:"max_matches_per_rule"`
	// MaxFindings bounds retained findings. Exceeding it leaves an explicit
	// completeness gap.
	MaxFindings int `json:"max_findings"`
	// MaxCaptureBytes bounds captured bytes across every target in a run.
	MaxCaptureBytes int64 `json:"max_capture_bytes"`
	// MaxExtractedBytes bounds extracted bytes across every target in a run.
	MaxExtractedBytes int64 `json:"max_extracted_bytes"`
	// MaxCaptureFiles bounds captured files across every target in a run.
	MaxCaptureFiles int `json:"max_capture_files"`
	// MaxCaptureEntries bounds inventoried entries across every target in a run.
	MaxCaptureEntries int `json:"max_capture_entries"`
	// MaxServiceRequests limits external traversal, advisory and review requests
	// across the run.
	MaxServiceRequests int `json:"max_service_requests"`
	// TimeoutNS records the operation timeout in nanoseconds.
	TimeoutNS int64 `json:"timeout_ns"`
	// ParserTimeoutNS records the cooperative parser timeout in nanoseconds.
	ParserTimeoutNS int64 `json:"parser_timeout_ns"`
	// Targets bounds concurrent target scans.
	Targets int `json:"target_workers"`
	// Workers bounds analyzer workers shared across the run's targets.
	Workers int `json:"workers"`
}

// ParserCapability describes a compiled parser backend, including explicit
// unavailability.
type ParserCapability struct {
	// Format names the source format served by the parser backend.
	Format string `json:"format"`
	// Name identifies the parser backend.
	Name string `json:"name"`
	// Version records the compiled parser backend revision.
	Version string `json:"version"`
	// Available reports whether this build provides the parser backend.
	Available bool `json:"available"`
	// Reason explains why the parser backend is unavailable.
	Reason string `json:"reason,omitempty"`
}

// Capabilities reports the selected plan and compiled parser and signature
// availability before execution.
type Capabilities struct {
	// Plan describes the work selected before execution.
	Plan InspectionPlan `json:"plan"`
	// Parsers lists parser backends compiled into this build and their
	// availability.
	Parsers []ParserCapability `json:"parsers"`
	// Signatures describes the compiled signature backend and its availability.
	Signatures SignatureCapability `json:"signatures"`
}

// InspectionCheck records selection and availability of a check before
// execution.
type InspectionCheck struct {
	// ID names a check whose selection and availability are recorded before
	// execution.
	ID string `json:"id"`
	// Selected reports whether this check belongs to the requested plan.
	Selected bool `json:"selected"`
	// Available reports whether the check's required implementation is available
	// in this build.
	Available bool `json:"available"`
	// Reason explains unavailability or configuration requirements.
	Reason string `json:"reason,omitempty"`
}

// InspectionEgress records explicit permissions for the three kinds of
// outbound data transfer.
type InspectionEgress struct {
	// Download permits explicitly requested remote capture and selected external
	// traversal.
	Download bool `json:"download"`
	// VulnerabilityNetwork permits network advisory lookup independently of source
	// upload.
	VulnerabilityNetwork bool `json:"vulnerability_network"`
	// SourceUpload permits bounded source excerpts to be sent to the reviewer.
	SourceUpload bool `json:"source_upload"`
}

// Enabled reports requested data transfer independently of service availability.
func (e InspectionEgress) Enabled() bool {
	return e.Download || e.SourceUpload || e.VulnerabilityNetwork
}

// HasServiceChecks distinguishes explicitly selected external-service passes
// (including cache-backed ones) from the static checks in a captured plan.
func (p InspectionPlan) HasServiceChecks() bool {
	for _, check := range p.Checks {
		if check.Selected && (check.ID == "semantic" || check.ID == "vulnerabilities") {
			return true
		}
	}

	return false
}
