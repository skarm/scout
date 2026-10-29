package update

import (
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

func (b *builder) findingGroups(r report.Analysis, x inventory) map[string][]report.Finding {
	groups := map[string][]report.Finding{}

	for _, f := range r.Findings {
		if !b.step() {
			return groups
		}

		g := locationKey(f, x)
		groups[g] = append(groups[g], f)
	}

	for _, g := range sortedKeys(groups, nil) {
		sort.Slice(groups[g], func(i, j int) bool {
			a, z := groups[g][i], groups[g][j]
			if a.Location.ByteStart != z.Location.ByteStart {
				return a.Location.ByteStart < z.Location.ByteStart
			}

			if a.Location.ByteEnd != z.Location.ByteEnd {
				return a.Location.ByteEnd < z.Location.ByteEnd
			}

			return a.ID < z.ID
		})
	}

	return groups
}

func (b *builder) findings() {
	a, z := b.findingGroups(b.before, b.old), b.findingGroups(b.after, b.next)
	oldChecks := checkIndex(b.before, b.old)

	newChecks := checkIndex(b.after, b.next)
	for _, g := range sortedKeys(a, z) {
		if !b.step() {
			return
		}

		left, right := a[g], z[g]

		for i := 0; i < max(len(left), len(right)); i++ {
			if !b.step() {
				return
			}

			c := b.findingSides(left, right, i)
			b.classifyFinding(left, right, i, &c, oldChecks, newChecks)

			if c.Change == "" {
				continue
			}

			b.delta.Counts.FindingChanges++
			if b.retain() {
				b.delta.Findings = append(b.delta.Findings, c)
			}
		}
	}
}

func (b *builder) classifyFinding(left, right []report.Finding, i int, c *report.FindingChange, oldChecks, newChecks map[string]report.FileCoverage) {
	switch {
	case i < min(len(left), len(right)):
		b.delta.Counts.PersistentFindings++
		c.Change = b.persistentFindingChange(left[i], right[i])
	case i < len(right):
		c.Change = "introduced"
		if !absenceCheckComplete(right[i], c.ObjectID, b.old, oldChecks) {
			c.Change = "unverified"

			b.issue("previous_finding_state_unverified")
		} else {
			b.delta.Counts.IntroducedFindings++
		}
	case i < len(left):
		c.Change = "not_observed"

		b.delta.Counts.UnobservedFindings++
		if !absenceCheckComplete(left[i], c.ObjectID, b.next, newChecks) {
			c.Change = "unverified"

			b.issue("finding_absence_unverified")
		}
	}
}

func (b *builder) persistentFindingChange(before, after report.Finding) string {
	if b.contextKey(before, b.oldComponents) != b.contextKey(after, b.newComponents) {
		return "context_changed"
	}

	if before.Location.ByteStart != after.Location.ByteStart || before.Location.ByteEnd != after.Location.ByteEnd {
		return "relocated"
	}

	return ""
}

func (b *builder) findingSides(left, right []report.Finding, index int) report.FindingChange {
	c := report.FindingChange{}

	if index < len(left) {
		f := left[index]
		c.BeforeID = f.ID
		location := f.Location
		c.BeforeLocation = &location
		c.RuleID = f.RuleID
		c.ObjectID = b.old.objectKey(location.Path)
	}

	if index < len(right) {
		f := right[index]
		c.AfterID = f.ID
		location := f.Location
		c.AfterLocation = &location
		c.RuleID = f.RuleID
		c.ObjectID = b.next.objectKey(location.Path)
	}

	return c
}

func checkIndex(r report.Analysis, x inventory) map[string]report.FileCoverage {
	out := make(map[string]report.FileCoverage, len(r.Coverage.Files))
	for _, f := range r.Coverage.Files {
		out[x.objectKey(f.Path)] = f
	}

	return out
}

func findingLanguage(method string) string {
	lang := ""

	switch {
	case strings.HasPrefix(method, "go-ast"):
		lang = language.Go
	case strings.HasPrefix(method, "shell-"):
		lang = language.Shell
	case method == "json-configuration":
		lang = language.JSON
	}

	return lang
}

func parserCoverageComplete(units []report.UnitCoverage, language string) bool {
	found := false

	for _, unit := range units {
		if unit.Language == language {
			found = true

			if unit.Status != report.UnitParsedLimited {
				return false
			}
		}
	}

	return found
}

func absenceCheckComplete(f report.Finding, objectID string, x inventory, checks map[string]report.FileCoverage) bool {
	o := x.byKey[objectID]
	if o == nil {
		return x.complete
	}

	if o.file.Status != report.CaptureCaptured {
		return false
	}

	coverage, ok := checks[objectID]
	if !ok {
		return false
	}

	if slices.Contains(coverage.Gaps, "report_finding_limit") {
		return false
	}

	completed := false

	for _, c := range coverage.Checks {
		if c.AnalyzerID == f.RuleID {
			completed = c.Status == report.OutcomeCompleted
		}
	}

	if !completed {
		return false
	}

	lang := findingLanguage(f.Method)
	if lang != "" {
		return parserCoverageComplete(coverage.Units, lang)
	}

	return true
}
