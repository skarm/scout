package scout

import (
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

// Capabilities returns this Scanner's configured plan and the parser and
// signature backends available in the build.
func (s *Scanner) Capabilities() report.Capabilities {
	return report.Capabilities{
		Plan:       s.InspectionPlan(),
		Parsers:    ParserCapabilities(),
		Signatures: signatures.Backend(),
	}
}

// ParserCapabilities reports every compiled grammar without opening inputs or
// constructing a Scanner. Availability does not imply exhaustive semantics.
func ParserCapabilities() []report.ParserCapability { return parse.Capabilities() }

func inspectionPlan(o Options, c Checks) report.InspectionPlan {
	p := report.InspectionPlan{
		Scope:            "selected syntax and rules; no exhaustive language or runtime proof",
		Name:             string(o.Profile),
		RequestedProfile: string(o.Profile),
		Checks:           []report.InspectionCheck{},
		Requirements:     []string{},
	}
	add := func(id string, selected, available bool, reason string) {
		p.Checks = append(p.Checks, report.InspectionCheck{
			ID:        id,
			Selected:  selected,
			Available: available,
			Reason:    reason,
		})
	}
	add("builtins", true, true, "")
	add("adapted_patterns", c.Patterns, true, "")
	add("external_closure", o.External != nil, true, "")

	for _, parser := range []struct {
		name    string
		enabled bool
	}{{name: language.Python, enabled: c.Python}, {name: language.YAML, enabled: c.YAML}, {name: language.TOML, enabled: c.TOML}} {
		b := frontend.BackendFor(parser.name)
		add(parser.name, parser.enabled, b.Available, b.Reason)
	}

	b := signatures.Backend()
	add("yara", c.YARA, b.Available, b.Reason)
	add("vulnerabilities", o.Vulnerabilities != nil, true, "")
	add("semantic", o.Review != nil, true, "")
	p.Egress.Download = o.Download != nil && o.Download.Enabled
	p.Egress.VulnerabilityNetwork = o.Vulnerabilities != nil && o.Vulnerabilities.AllowNetwork
	p.Egress.SourceUpload = o.Review != nil && o.Review.Settings.AllowSourceUpload
	l := o.Limits
	p.Limits = &report.ExecutionLimits{
		Capture:            o.captureLimits(),
		Extraction:         l.Extraction,
		MaxOperations:      l.Analysis.MaxOperations,
		MaxMatchesPerRule:  l.Analysis.MaxMatchesPerRule,
		MaxFindings:        l.Retention.MaxFindings,
		MaxCaptureBytes:    l.MaxCaptureBytes,
		MaxExtractedBytes:  l.MaxExtractedBytes,
		MaxCaptureFiles:    l.MaxCaptureFiles,
		MaxCaptureEntries:  l.MaxCaptureEntries,
		MaxServiceRequests: l.MaxServiceRequests,
		TimeoutNS:          int64(l.Timeout),
		ParserTimeoutNS:    int64(l.Analysis.ParserTimeout),
		Targets:            o.Concurrency.Targets,
		Workers:            o.Concurrency.Workers,
	}

	return p
}
