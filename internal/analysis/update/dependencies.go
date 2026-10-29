package update

import (
	"sort"

	"github.com/skarm/scout/report"
)

func (b *builder) dependencyGroups(r report.Analysis, x inventory) map[string][]report.Dependency {
	groups := map[string][]report.Dependency{}

	for _, d := range r.Dependencies.Declarations {
		if !b.step() {
			return groups
		}

		g := key(x.objectKey(d.Source.Path), d.Ecosystem, d.Module)
		groups[g] = append(groups[g], d)
	}

	for _, g := range sortedKeys(groups, nil) {
		sort.Slice(groups[g], func(i, j int) bool { return groups[g][i].Source.ByteStart < groups[g][j].Source.ByteStart })
	}

	return groups
}

func (b *builder) dependencies() {
	oldChecks, newChecks := dependencyChecks(b.before, b.old), dependencyChecks(b.after, b.next)

	a, z := b.dependencyGroups(b.before, b.old), b.dependencyGroups(b.after, b.next)
	for _, g := range sortedKeys(a, z) {
		if !b.step() {
			return
		}

		left, right := a[g], z[g]
		if dependencySignatures(left) == dependencySignatures(right) {
			continue
		}

		c := report.DependencyChange{
			GroupID: g,
			Before:  append([]report.Dependency{}, left...),
			After:   append([]report.Dependency{}, right...),
		}
		if len(left) == 0 {
			c.ObjectID = b.next.objectKey(right[0].Source.Path)
		} else {
			c.ObjectID = b.old.objectKey(left[0].Source.Path)
		}

		c.Change = observationChange(len(left), len(right), dependencyAbsenceKnown(c.ObjectID, b.old, oldChecks), dependencyAbsenceKnown(c.ObjectID, b.next, newChecks))
		if c.Change == "unverified" {
			b.issue("dependency_absence_unverified")
		}

		b.delta.Counts.DependencyChanges++
		if b.retain() {
			b.delta.Dependencies = append(b.delta.Dependencies, c)
		}
	}
}

func dependencySignature(d report.Dependency) string {
	// The replacement source hash is needed even for local replacement paths,
	// whose sensitive literal values are deliberately not reported.
	replacement := ""
	if d.ReplacementSource != nil {
		replacement = d.ReplacementSource.SpanSHA256
	}

	return digest(struct {
		Ecosystem, Module, Version, Semantics, Replacement, ReplacementModule, ReplacementVersion, ReplacementSHA string
		Indirect                                                                                                  bool
	}{
		Ecosystem:          d.Ecosystem,
		Module:             d.Module,
		Version:            d.DeclaredVersion,
		Semantics:          d.VersionSemantics,
		Replacement:        d.Replacement,
		ReplacementModule:  d.ReplacementModule,
		ReplacementVersion: d.ReplacementVersion,
		ReplacementSHA:     replacement,
		Indirect:           d.Indirect,
	})
}

func dependencySignatures(ds []report.Dependency) string {
	x := make([]string, 0, len(ds))
	for _, d := range ds {
		x = append(x, dependencySignature(d))
	}

	sort.Strings(x)

	return digest(x)
}

func dependencyChecks(r report.Analysis, x inventory) map[string]bool {
	out := map[string]bool{}

	for _, m := range r.Dependencies.Manifests {
		id := x.objectKey(m.Path)

		ok := m.InventoryComplete()
		if prior, exists := out[id]; exists {
			ok = ok && prior
		}

		out[id] = ok
	}

	return out
}

func dependencyAbsenceKnown(id string, x inventory, checks map[string]bool) bool {
	o := x.byKey[id]
	if o == nil {
		return x.complete
	}

	return o.file.Status == report.CaptureCaptured && checks[id]
}

// Added/removed declarations need a complete observation on the absent side.
func observationChange(before, after int, oldKnown, newKnown bool) string {
	if before == 0 {
		if !oldKnown {
			return "unverified"
		}

		return "added"
	}

	if after == 0 {
		if !newKnown {
			return "unverified"
		}

		return "removed"
	}

	return "changed"
}
