package report

// CloneRule isolates published reports from the engine's immutable rule catalog.
// In particular, mutating a prior report must not change a later scan's guidance.
func CloneRule(r Rule) Rule {
	if r.Guidance != nil {
		g := *r.Guidance
		g.ReviewChecks = append([]string(nil), g.ReviewChecks...)
		g.BenignConsiderations = append([]string(nil), g.BenignConsiderations...)
		g.Sources = append([]GuidanceReference(nil), g.Sources...)
		r.Guidance = &g
	}

	return r
}

// CloneRules returns a deep copy of rules, including their guidance and source
// references.
func CloneRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = CloneRule(r)
	}

	return out
}
