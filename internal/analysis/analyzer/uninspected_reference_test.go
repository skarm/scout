package analyzer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestUninspectedReferenceUsesCapturedDeclarationIdentity(t *testing.T) {
	ctx := context.Background()
	file := artifact.NewFile("config.json", []byte(`{"first":"./one.sh","second":"./two.sh"}`), false)
	doc := document.Prepare(ctx, file)
	first := report.SourceRef{Path: file.Metadata().Path, SHA256: file.Metadata().SHA256, ByteStart: 10, ByteEnd: 18}
	second := first
	second.ByteStart, second.ByteEnd = 30, 38
	stale, foreign := first, first
	stale.SHA256 = artifact.Hash([]byte("older captured bytes"))
	foreign.Path = "other.json"
	graph := report.ComponentGraph{References: []report.ComponentReference{
		{Status: "unresolved", Reason: "handler_not_captured"},
		{Status: "resolved", Reason: "handler_not_captured", Source: &first},
		{Status: "unresolved", Reason: "remote_implementation_not_scanned", Source: &first},
		{Status: "unresolved", Reason: "handler_not_captured", Source: &stale},
		{Status: "unresolved", Reason: "handler_not_captured", Source: &foreign},
		{Status: "unresolved", Reason: "handler_not_captured", Source: &first},
		{Status: "unresolved", Reason: "component_not_captured", Source: &second},
	}}
	registry := []analyzer.Analyzer{pluginRule(t, "NV-SC9"), agentRule(t, "PI001")}
	bound := analyzer.BindGraph(registry, []document.File{doc}, graph)
	if registry[0].AppliesTo(doc) || !bound[0].AppliesTo(doc) || bound[1] != registry[1] {
		t.Fatal("binding changed the registry or lost captured scope")
	}
	first.ByteStart = 999 // Binding retains immutable spans, not graph source pointers.
	for _, budget := range []int{-1, 0, 1, 2, 3} {
		result, err := bound[0].Find(ctx, doc, budget)
		want := min(max(0, budget), 2)
		if err != nil || len(result.Matches) != want || result.Truncated != (budget < 2) {
			t.Fatalf("budget %d: %+v %v", budget, result, err)
		}
		for i, match := range result.Matches {
			start, end := 10, 18
			if i == 1 {
				start, end = 30, 38
			}
			if match.Start != start || match.End != end {
				t.Fatal("declaration order or captured span changed", match)
			}
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if result, err := bound[0].Find(cancelled, doc, 10); !errors.Is(err, context.Canceled) || len(result.Matches) != 0 || result.Truncated {
		t.Fatal("cancelled discovery published a reference", result, err)
	}
	other := document.Prepare(ctx, artifact.NewFile("other.json", []byte("{}"), false))
	if bound[0].AppliesTo(other) {
		t.Fatal("path-only reference escaped its captured digest")
	}
	if result, err := bound[0].Find(ctx, other, 10); err != nil || len(result.Matches) != 0 || result.Truncated {
		t.Fatal("uncaptured declaration produced a finding", result, err)
	}
}

func TestUninspectedReferenceProjectsRealHarnessObligation(t *testing.T) {
	ctx := context.Background()
	file := artifact.NewFile(".claude-plugin/plugin.json", []byte(`{"name":"p","hooks":"./custom.json"}`), false)
	docs := document.PrepareAll(ctx, []artifact.File{file})
	inventory := []report.File{file.Metadata(), {Path: "custom.json", Status: "skipped", Reason: "size_limit"}}
	graph := harness.Discover(ctx, inventory, docs, report.ExtractionReport{}, report.HarnessOptions{Host: "claude-code"})
	checks := analyzer.BindGraph([]analyzer.Analyzer{pluginRule(t, "NV-SC9")}, docs, graph)
	result, err := checks[0].Find(ctx, docs[0], 10)
	if err != nil || len(result.Matches) != 1 || result.Truncated {
		t.Fatal("missing captured inspection obligation", graph.References, result, err)
	}
	match := result.Matches[0]
	if file.Content()[match.Start:match.End] != `"./custom.json"` {
		t.Fatal("finding no longer points to the local declaration", match)
	}
}
