package environment_test

import (
	"context"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/environment"
	"github.com/skarm/scout/report"
)

func TestEnvironmentBudgetsRetainEvidenceAndExposeOmissions(t *testing.T) {
	targets := []report.TargetResult{{ID: "a", State: report.RunComplete}, {ID: "b", State: report.RunComplete}, {ID: "c", State: report.RunComplete}}
	surfaces := make([]bundle.Surface, len(targets))
	for i := range surfaces {
		surfaces[i] = bundle.Surface{Complete: true, Facts: []bundle.SurfaceFact{{Kind: "tool_identifier", Value: "same", Scope: "tools.json", Source: report.SourceRef{Path: "tools.json", ByteEnd: 4}}}}
	}
	result := environment.Build(context.Background(), surfaces, targets, 1, 100)
	if result.Completeness != report.Partial || len(result.Observations) != 1 || !slices.Contains(result.Issues, "observation_limit") {
		t.Fatalf("observation cap hid omissions: %+v", result)
	}
	if len(result.Observations[0].Evidence) != 2 || result.Observations[0].Evidence[0].TargetID == result.Observations[0].Evidence[1].TargetID {
		t.Fatalf("retained observation lost evidence: %+v", result)
	}
	result = environment.Build(context.Background(), surfaces, targets, 100, 1)
	if result.Completeness != report.Partial || !slices.Contains(result.Issues, "operation_limit") {
		t.Fatalf("operation cap allowed: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = environment.Build(ctx, nil, nil, 1, 100)
	if result.Completeness != report.Partial || !slices.Contains(result.Issues, "cancelled") {
		t.Fatal("cancelled empty environment completed")
	}
}

func TestDifferentIdentifierKindsAndLocalDuplicatesAreNotCrossComponentCollisions(t *testing.T) {
	surface := bundle.Surface{Complete: true, Facts: []bundle.SurfaceFact{
		{Kind: "tool_identifier", Value: "same", Source: report.SourceRef{Path: "a.json", ByteEnd: 1}},
		{Kind: "tool_identifier", Value: "same", Source: report.SourceRef{Path: "a.json", ByteStart: 2, ByteEnd: 3}},
		{Kind: "mcp_identifier", Value: "same", Source: report.SourceRef{Path: "b.json", ByteEnd: 1}},
	}}
	result := environment.Build(context.Background(), []bundle.Surface{surface}, []report.TargetResult{{ID: "a", State: report.RunComplete}}, 100, 100)
	if result.Completeness != report.Complete || len(result.Observations) != 0 {
		t.Fatalf("unrelated identifiers collided: %+v", result)
	}
}
