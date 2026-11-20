package harness_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestArchiveNamedSnapshotKeepsDistinctPluginNamespace(t *testing.T) {
	const manifest = "fixture/.claude-plugin/plugin.json"
	const member = report.ObjectPathPrefix + "fixture/manifest.json"
	root := artifact.NewFile(manifest, []byte(`{"name":"root-fixture"}`), false)
	carrier := artifact.NewFile("snapshot", []byte("Synthetic capture inventory"), false)
	derived := artifact.NewFile(member, []byte(`{"name":"archive-fixture"}`), false)
	inventory := []report.File{root.Metadata(), carrier.Metadata()}
	extraction := report.ExtractionReport{Objects: []report.DerivedObject{{
		ParentPath: carrier.Metadata().Path, MemberName: manifest,
		File: derived.Metadata(), Role: "archive_member", ExtractorID: "zip32",
	}}}
	docs := document.PrepareAll(t.Context(), []artifact.File{root, carrier, derived})
	locations := document.CapturedAddresses(docs, extraction)
	if locations[root.Metadata().Path].Namespace == locations[member].Namespace {
		t.Error("standalone and archive files share a namespace")
	}
	graph := harness.Discover(t.Context(), inventory, docs, extraction, report.HarnessOptions{})
	if len(graph.Plugins) != 2 {
		t.Fatalf("expected both plugin interpretations, got %+v", graph.Plugins)
	}
	ids := map[string]bool{}
	declared := map[string]bool{}
	for _, p := range graph.Plugins {
		if ids[p.ID] {
			t.Fatal("different packages have one plugin identity")
		}
		ids[p.ID] = true
		for _, name := range p.Manifests {
			declared[name] = true
		}
	}
	if !declared[manifest] || !declared[member] {
		t.Fatal("missing manifest provenance", declared)
	}
}
