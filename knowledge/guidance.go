package knowledge

import "github.com/skarm/scout/report"

// WithGuidance attaches catalog guidance without changing the detector result.
func WithGuidance(r report.Rule) report.Rule {
	if r.Guidance == nil {
		if g, ok := Lookup(r.ID); ok {
			r.Guidance = &g
		}
	}

	return report.CloneRule(r)
}
