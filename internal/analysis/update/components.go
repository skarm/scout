package update

import (
	"sort"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

type componentRecord struct {
	node                       report.Component
	group, object, fingerprint string
}
type componentIndex struct {
	byID    map[string]*componentRecord
	groups  map[string][]*componentRecord
	plugins map[string]string
}

func (b *builder) components(r report.Analysis, x inventory) componentIndex {
	out := componentIndex{
		byID:    map[string]*componentRecord{},
		groups:  map[string][]*componentRecord{},
		plugins: map[string]string{},
	}

	if !b.componentOwners(r, x, out) {
		return out
	}

	if !b.componentNodes(r, x, out) {
		return out
	}

	links := map[string][]string{}
	if !b.componentEdges(r, x, out, links) {
		return out
	}

	if !b.componentReferenceLinks(r.Components.References, x, out, links) {
		return out
	}

	for _, id := range sortedKeys(out.byID, nil) {
		if !b.step() {
			return out
		}

		c := out.byID[id]
		l := links[id]
		sort.Strings(l)
		c.fingerprint = key(c.node.Kind, c.node.Host, c.node.Activation, spanKey(c.node.Source, x), digest(l))
	}

	return out
}

func (b *builder) componentOwners(r report.Analysis, x inventory, out componentIndex) bool {
	for _, p := range r.Components.Plugins {
		if !b.step() {
			return false
		}

		ns := p.Namespace
		if ns != "snapshot" {
			ns = x.objectKey(ns)
		}

		out.plugins[p.ID] = key("plugin", ns, p.Root, p.Host, p.AdapterID, p.AdapterVersion, p.Contract)
	}

	return true
}

func (b *builder) componentNodes(r report.Analysis, x inventory, out componentIndex) bool {
	for _, c := range r.Components.Components {
		if !b.step() {
			return false
		}

		pid := "standalone"

		if c.PluginID != "" {
			var ok bool

			pid, ok = out.plugins[c.PluginID]
			if !ok {
				b.issue("unresolved_component_owner")

				pid = key("unknown-plugin", c.PluginID)
			}
		}

		objectID := ""
		if c.Path != "" {
			objectID = x.objectKey(c.Path)
		}

		group := key("component", pid, c.Kind, c.Host, objectID, c.PackagePath)

		rec := &componentRecord{node: c, group: group, object: objectID}
		if _, ok := out.byID[c.ID]; ok {
			b.issue("duplicate_component_id")
			continue
		}

		out.byID[c.ID] = rec
		out.groups[group] = append(out.groups[group], rec)
	}

	return true
}

func (b *builder) componentEdges(r report.Analysis, x inventory, out componentIndex, links map[string][]string) bool {
	for _, e := range r.Components.Edges {
		if !b.step() {
			return false
		}

		from, to := out.byID[e.From], out.byID[e.To]
		if from == nil || to == nil {
			b.issue("unresolved_component_edge")
			continue
		}

		f := key(e.Relation, e.Basis, e.Activation, from.group, to.group, spanKey(e.Source, x))
		links[e.From] = append(links[e.From], key("outgoing", f))
		links[e.To] = append(links[e.To], key("incoming", f))
	}

	return true
}

func (b *builder) componentReferenceLinks(refs []report.ComponentReference, x inventory, components componentIndex, links map[string][]string) bool {
	for _, ref := range refs {
		if !b.step() {
			return false
		}

		if components.byID[ref.ComponentID] == nil {
			b.issue("unresolved_component_reference")
			continue
		}

		target := ""

		if ref.TargetID != "" {
			if record := components.byID[ref.TargetID]; record != nil {
				target = record.group
			} else {
				b.issue("unresolved_reference_target")

				target = key("unknown-target", ref.TargetID)
			}
		}

		links[ref.ComponentID] = append(links[ref.ComponentID], key("reference", ref.Kind, ref.Status, ref.Reason, target, spanKey(ref.Source, x)))
	}

	return true
}

func (b *builder) componentChanges() {
	oldChecks, newChecks := checkIndex(b.before, b.old), checkIndex(b.after, b.next)

	oldReliable, newReliable := componentDiscoveryReliable(b.before), componentDiscoveryReliable(b.after)
	for _, g := range sortedKeys(b.oldComponents.groups, b.newComponents.groups) {
		if !b.step() {
			return
		}

		a, z := sortedComponents(b.oldComponents.groups[g]), sortedComponents(b.newComponents.groups[g])
		c := report.ComponentChange{
			GroupID:          g,
			BeforeIDs:        ids(a),
			AfterIDs:         ids(z),
			NotMatchedBefore: []string{},
			NotMatchedAfter:  []string{},
		}

		var representative *componentRecord
		if len(z) > 0 {
			representative = z[0]
		} else {
			representative = a[0]
		}

		c.Kind = representative.node.Kind
		c.Host = representative.node.Host
		c.ObjectID = representative.object

		if !b.matchComponentOccurrences(a, z, &c) {
			return
		}

		if len(c.NotMatchedBefore)+len(c.NotMatchedAfter) == 0 {
			continue
		}

		c.Change = observationChange(len(a), len(z), componentAbsenceKnown(c.ObjectID, b.old, oldChecks, oldReliable), componentAbsenceKnown(c.ObjectID, b.next, newChecks, newReliable))
		if c.Change == "unverified" {
			b.issue("component_absence_unverified")
		}

		b.delta.Counts.ComponentChanges++
		if b.retain() {
			b.delta.Components = append(b.delta.Components, c)
		}
	}
}

func (b *builder) matchComponentOccurrences(before, after []*componentRecord, change *report.ComponentChange) bool {
	i, j := 0, 0
	for i+j < len(before)+len(after) {
		if !b.step() {
			return false
		}

		switch {
		case i == len(before):
			change.NotMatchedAfter = append(change.NotMatchedAfter, after[j].node.ID)
			j++
		case j == len(after):
			change.NotMatchedBefore = append(change.NotMatchedBefore, before[i].node.ID)
			i++
		case before[i].fingerprint == after[j].fingerprint:
			change.Matched++
			i++
			j++
		case before[i].fingerprint < after[j].fingerprint:
			change.NotMatchedBefore = append(change.NotMatchedBefore, before[i].node.ID)
			i++
		default:
			change.NotMatchedAfter = append(change.NotMatchedAfter, after[j].node.ID)
			j++
		}
	}

	return true
}

func (b *builder) contextKey(f report.Finding, components componentIndex) string {
	values := make([]string, 0, len(f.Contexts))
	for _, c := range f.Contexts {
		if !b.step() {
			break
		}

		group := key("unknown", c.ComponentID)
		if node := components.byID[c.ComponentID]; node != nil {
			group = node.group
		} else {
			b.issue("unresolved_finding_context")
		}

		values = append(values, key(group, c.Host, c.Relation, c.Activation))
	}

	sort.Strings(values)

	return digest(values)
}

func sortedComponents(in []*componentRecord) []*componentRecord {
	out := append([]*componentRecord(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].fingerprint != out[j].fingerprint {
			return out[i].fingerprint < out[j].fingerprint
		}

		a, z := out[i].node.Source, out[j].node.Source
		if a != nil && z != nil && a.ByteStart != z.ByteStart {
			return a.ByteStart < z.ByteStart
		}

		return out[i].node.ID < out[j].node.ID
	})

	return out
}

func ids(in []*componentRecord) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.node.ID)
	}

	return out
}

// This checks whether absence can be interpreted as a change to observed
// declarations. Even a known absence is not proof about host runtime activation.
func componentDiscoveryReliable(r report.Analysis) bool {
	for _, issue := range r.Components.Issues {
		if issue.Status == "invalid" || issue.Status == report.OutcomeFailed ||
			strings.Contains(issue.Code, "limit") || strings.Contains(issue.Code, "cancelled") ||
			strings.Contains(issue.Code, "unavailable") || strings.Contains(issue.Code, "not_captured") {
			return false
		}
	}

	return true
}

func componentAbsenceKnown(id string, x inventory, checks map[string]report.FileCoverage, reliable bool) bool {
	if !reliable {
		return false
	}

	o := x.byKey[id]
	if o == nil {
		return x.complete
	}

	if o.file.Status != report.CaptureCaptured {
		return false
	}

	c, ok := checks[id]
	if !ok {
		return false
	}

	for _, unit := range c.Units {
		if unit.Language == language.JSON && unit.Status != report.UnitParsedLimited {
			return false
		}
	}

	return true
}
