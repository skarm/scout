package update_test

import (
	"context"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/update"
	"github.com/skarm/scout/report"
)

func TestManifestSignalsReflectSourceBoundDeclarationChanges(t *testing.T) {
	for _, tc := range []struct{ before, after, rule string }{
		{before: `{"permissions":["read"]}`, after: `{"permissions":["read","write"]}`, rule: "NV-RP1"},
		{before: `{"permissions":["read","write"]}`, after: `{"permissions":["read"]}`, rule: ""},
		{before: `{}`, after: `{"allowed-tools":["Bash"]}`, rule: "NV-RP1"},
		{before: `{"allowed-tools":"Read"}`, after: `{}`, rule: ""},
		{before: `{"triggers":["old"]}`, after: `{"triggers":["new"]}`, rule: "NV-RP2"},
		{before: `{"triggers":["old"]}`, after: `{}`, rule: "NV-RP2"},
		{
			before: `{"parameters":{"arg":{"type":"string"}}}`,
			after:  `{"parameters":{"arg":{"type":"number"}}}`,
			rule:   "NV-RP3",
		},
		{before: `{"parameters":{"arg":1}}`, after: `{"parameters":{"arg":1}}`, rule: ""},
	} {
		t.Run(tc.before+tc.after, func(t *testing.T) {
			before, after := scanText(t, "manifest.json", tc.before), scanText(t, "manifest.json", tc.after)
			delta, err := update.Build(context.Background(), before, after, report.DefaultUpdateOptions())
			if err != nil {
				t.Fatal(err)
			}
			if tc.rule == "" {
				if len(delta.ManifestSignals) != 0 {
					t.Fatal(delta.ManifestSignals)
				}
				return
			}
			if len(delta.ManifestSignals) != 1 || delta.ManifestSignals[0].RuleID != tc.rule || delta.Counts.ManifestSignals != 1 {
				t.Fatal(delta)
			}
			signal := delta.ManifestSignals[0]
			if signal.Before == nil && signal.After == nil {
				t.Fatal("source evidence absent", signal)
			}
		})
	}
	before := scanText(t, "manifest.json", `{"permissions":["read"]}`)
	after := scanText(t, "manifest.json", `{"permissions":[1]}`)
	delta, err := update.Build(context.Background(), before, after, report.DefaultUpdateOptions())
	if err != nil || !slices.Contains(delta.Issues, "manifest_declaration_unverified") || len(delta.ManifestSignals) != 0 {
		t.Fatal(err, delta)
	}
}

func TestComponentReferencesAndFindingContextsRemainComparable(t *testing.T) {
	before := scanText(t, "x.txt", "ordinary bytes")
	before.Components.Plugins = []report.PluginInterpretation{{ID: "p", Namespace: "snapshot", Root: ".", Host: "test"}}
	before.Components.Components = []report.Component{{
		ID:       "a",
		PluginID: "p",
		Path:     "x.txt",
		Kind:     "hook",
		Host:     "test",
	}, {
		ID:       "b",
		PluginID: "p",
		Path:     "x.txt",
		Kind:     "handler",
		Host:     "test",
	}}
	before.Components.References = []report.ComponentReference{{
		ID:          "r",
		ComponentID: "a",
		TargetID:    "b",
		Kind:        "handler",
		Status:      "resolved",
	}}
	before.Findings = []report.Finding{{
		ID:     "f",
		RuleID: "example",
		Method: "literal",
		Location: report.Location{
			Path:      "x.txt",
			ByteStart: 0,
			ByteEnd:   8,
		},
		Evidence: report.Evidence{SpanSHA256: "same"},
		Contexts: []report.FindingContext{{
			ComponentID: "a",
			Host:        "test",
			Relation:    "same_component_bytes",
		}},
	}}
	for _, tc := range []struct {
		name, change string
		alter        func(*report.Analysis)
	}{
		{
			name:   "relocated",
			change: "relocated",
			alter:  func(r *report.Analysis) { r.Findings[0].Location.ByteStart = 1; r.Findings[0].Location.ByteEnd = 9 },
		},
		{name: "context", change: "context_changed", alter: func(r *report.Analysis) {
			r.Findings[0].Contexts = []report.FindingContext{{
				ComponentID: "b",
				Host:        "test",
				Relation:    "declared_handler_reference",
			}}
		}},
		{name: "same", change: "", alter: func(r *report.Analysis) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			after.Findings = append([]report.Finding(nil), before.Findings...)
			tc.alter(&after)
			delta, err := update.Build(context.Background(), before, after, report.DefaultUpdateOptions())
			if err != nil {
				t.Fatal(err)
			}
			if tc.change == "" {
				if len(delta.Findings) != 0 {
					t.Fatal(delta.Findings)
				}
				return
			}
			if len(delta.Findings) != 1 || delta.Findings[0].Change != tc.change {
				t.Fatal(delta.Findings)
			}
		})
	}
	for _, tc := range []struct {
		issue string
		alter func(*report.Analysis)
	}{
		{
			issue: "unresolved_component_owner",
			alter: func(r *report.Analysis) { r.Components.Components[0].PluginID = "missing" },
		},
		{
			issue: "unresolved_component_reference",
			alter: func(r *report.Analysis) { r.Components.References[0].ComponentID = "missing" },
		},
		{
			issue: "unresolved_reference_target",
			alter: func(r *report.Analysis) { r.Components.References[0].TargetID = "missing" },
		},
		{
			issue: "unresolved_finding_context",
			alter: func(r *report.Analysis) { r.Findings[0].Contexts = []report.FindingContext{{ComponentID: "missing"}} },
		},
	} {
		t.Run(tc.issue, func(t *testing.T) {
			after := before
			after.Components.Components = append([]report.Component(nil), before.Components.Components...)
			after.Components.References = append([]report.ComponentReference(nil), before.Components.References...)
			after.Findings = append([]report.Finding(nil), before.Findings...)
			tc.alter(&after)
			delta, err := update.Build(context.Background(), before, after, report.DefaultUpdateOptions())
			if err != nil || !slices.Contains(delta.Issues, tc.issue) {
				t.Fatal(err, delta)
			}
		})
	}
}

func TestManifestComparisonRequiresAvailableParsedObjectOnBothSides(t *testing.T) {
	before := scanText(t, "manifest.json", `{"permissions":["read"]}`)
	after := scanText(t, "manifest.json", `{"permissions":["read","write"]}`)
	for _, tc := range []struct {
		name  string
		alter func(*report.Analysis)
	}{
		{name: "missing-object", alter: func(r *report.Analysis) { r.Metadata.Files[0].Path = "missing" }},
		{name: "unparsed", alter: func(r *report.Analysis) { r.Metadata.Files[0].Status = "failed" }},
		{name: "unmatched-format", alter: func(r *report.Analysis) { r.Metadata.Files[0].Format = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := after
			changed.Metadata.Files = append([]report.MetadataFile(nil), after.Metadata.Files...)
			tc.alter(&changed)
			delta, err := update.Build(context.Background(), before, changed, report.DefaultUpdateOptions())
			if err != nil || len(delta.ManifestSignals) != 0 {
				t.Fatal(err, delta)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	delta, err := update.Build(cancelled, before, after, report.DefaultUpdateOptions())
	if err == nil || delta.Completeness != report.Partial {
		t.Fatal(delta, err)
	}
}
