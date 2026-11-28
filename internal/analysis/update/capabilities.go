package update

import (
	"cmp"
	"slices"

	"github.com/skarm/scout/internal/analysis/environment"
	"github.com/skarm/scout/report"
)

type capabilityKey struct{ kind, path, value string }

func (b *builder) capabilities(previous, candidate environment.Surface) {
	delta := &report.CapabilityDelta{Changes: []report.CapabilityChange{}}
	b.delta.Capabilities = delta

	status := "introduced"

	if !previous.Complete || !b.old.complete {
		b.issue("previous_capabilities_incomplete")

		status = "unverified"
	}

	if !candidate.Complete || !b.next.complete {
		b.issue("candidate_capabilities_incomplete")
	}

	seen := make(map[capabilityKey]struct{}, len(previous.Facts)+len(candidate.Facts))
	for _, fact := range previous.Facts {
		if !b.step() {
			return
		}

		if fact.Line > 0 {
			seen[capabilityKey{fact.Kind, b.old.objectKey(fact.Source.Path), fact.Value}] = struct{}{}
		}
	}

	// The first source line is the representative for repeated uses of the same
	// capability and destination in a file. Line shifts alone are immaterial.
	slices.SortFunc(candidate.Facts, func(a, c environment.SurfaceFact) int {
		return cmp.Or(cmp.Compare(a.Source.Path, c.Source.Path), cmp.Compare(a.Source.ByteStart, c.Source.ByteStart),
			cmp.Compare(a.Kind, c.Kind), cmp.Compare(a.Value, c.Value))
	})

	for _, fact := range candidate.Facts {
		if !b.step() {
			return
		}

		if fact.Line == 0 {
			continue
		}

		key := capabilityKey{fact.Kind, b.next.objectKey(fact.Source.Path), fact.Value}
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		if !b.retain() {
			delta.Omitted++
			continue
		}

		change := report.CapabilityChange{Kind: fact.Kind, Status: status, Source: fact.Source, Line: fact.Line}
		if report.CapabilityHasDestination(fact.Kind) {
			change.Destination = fact.Value
		}

		delta.Changes = append(delta.Changes, change)
	}
}
