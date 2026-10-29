// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified SkillSpector RP1-RP3: compare both fresh source-bound metadata sets,
// retain hashes/evidence only and align archive members through object addresses.

package update

import "github.com/skarm/scout/report"

type manifestChanges struct{ added, changed, removed bool }

func (b *builder) manifests() {
	b.delta.ManifestSignals = []report.ManifestSignal{}

	old := b.previousManifests()
	if b.stopped {
		return
	}

	for _, next := range b.after.Metadata.Files {
		if !b.step() {
			return
		}

		o := b.next.byPath[next.Path]
		if o == nil {
			continue
		}

		previous, ok := old[key(o.key, next.Format)]
		if !ok || previous.Status != "parsed_subset" || next.Status != "parsed_subset" {
			continue
		}

		if !b.compareManifestFields(previous, next) {
			return
		}
	}
}

func (b *builder) previousManifests() map[string]report.MetadataFile {
	old := map[string]report.MetadataFile{}

	for _, f := range b.before.Metadata.Files {
		if !b.step() {
			return old
		}

		if o := b.old.byPath[f.Path]; o != nil {
			id := key(o.key, f.Format)
			if _, duplicate := old[id]; duplicate {
				b.issue("ambiguous_previous_manifest")
				continue
			}

			old[id] = f
		}
	}

	return old
}

func (b *builder) compareManifestFields(previous, next report.MetadataFile) bool {
	for _, field := range []string{"permissions", "allowed-tools", "triggers", "parameters"} {
		if !b.step() {
			return false
		}

		a, z := lastMetadataField(previous.Fields, field), lastMetadataField(next.Fields, field)
		if a == nil && z == nil {
			continue
		}

		if !metadataFieldsComplete(a, z) {
			b.issue("manifest_declaration_unverified")
			continue
		}

		changes, complete := b.compareManifestItems(a, z)
		if !complete {
			return false
		}

		b.recordManifestSignal(field, a, z, changes)
	}

	return true
}

func (b *builder) compareManifestItems(a, z *report.MetadataField) (manifestChanges, bool) {
	before, after := metadataItems(a), metadataItems(z)
	changes := manifestChanges{}

	for k, v := range after {
		if !b.step() {
			return changes, false
		}

		if old, ok := before[k]; !ok {
			changes.added = true
		} else if old != v {
			changes.changed = true
		}
	}

	for k := range before {
		if !b.step() {
			return changes, false
		}

		if _, ok := after[k]; !ok {
			changes.removed = true
		}
	}

	return changes, true
}

func (b *builder) recordManifestSignal(field string, a, z *report.MetadataField, changes manifestChanges) {
	rule, severity, kind := "NV-RP1", report.High, "permissions_expanded"

	switch field {
	case "triggers":
		rule, severity, kind = "NV-RP2", report.Medium, "triggers_modified"
	case "parameters":
		rule, severity, kind = "NV-RP3", report.Medium, "parameters_modified"
	}

	if rule == "NV-RP1" && !changes.added {
		return
	}

	if changes == (manifestChanges{}) {
		return
	}

	if !b.retain() {
		return
	}

	signal := report.ManifestSignal{RuleID: rule, Severity: severity, Field: field, Change: kind}

	if a != nil {
		ref := a.Source
		signal.Before = &ref
	}

	if z != nil {
		ref := z.Source
		signal.After = &ref
	}

	b.delta.ManifestSignals = append(b.delta.ManifestSignals, signal)
	b.delta.Counts.ManifestSignals++
}

func lastMetadataField(fields []report.MetadataField, name string) *report.MetadataField {
	var found *report.MetadataField

	for i := range fields {
		if fields[i].Name == name {
			found = &fields[i]
		}
	}

	return found
}

func metadataItems(field *report.MetadataField) map[string]string {
	out := map[string]string{}

	if field != nil {
		for _, item := range field.Items {
			out[item.NameSHA256] = item.ValueSHA256
		}
	}

	return out
}

func metadataFieldsComplete(fields ...*report.MetadataField) bool {
	for _, field := range fields {
		if field != nil && !field.ItemsComplete {
			return false
		}
	}

	return true
}
