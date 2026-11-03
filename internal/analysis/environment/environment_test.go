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

func TestCapabilityPairsRespectScopesAndBudgets(t *testing.T) {
	for _, tc := range []struct {
		input, effect string
		want          bool
	}{
		{"sensitive_read", "network", true},
		{"untrusted_input", "command_execution", true},
		{"untrusted_input", "file_write", true},
		{"untrusted_input", "infrastructure_mutation", true},
		{"untrusted_input", "network", false},
		{"sensitive_read", "file_write", false},
		{"command_execution", "untrusted_input", true},
	} {
		t.Run(tc.input+"/"+tc.effect, func(t *testing.T) {
			for _, same := range []bool{false, true} {
				scope := "effect/SKILL.md"
				if same {
					scope = "input/SKILL.md"
				}
				surface := bundle.Surface{Complete: true, Facts: []bundle.SurfaceFact{
					{Kind: tc.input, Scope: "input/SKILL.md", Source: report.SourceRef{Path: "input/run.sh", ByteEnd: 1}},
					{Kind: tc.effect, Scope: scope, Source: report.SourceRef{Path: "effect/run.sh", ByteEnd: 1}},
				}}
				targets := []report.TargetResult{{ID: "root", State: report.RunComplete}}
				out := environment.Build(t.Context(), []bundle.Surface{surface}, targets, 10, 100)
				if (len(out.Observations) == 1) != (tc.want && !same) || out.Completeness != report.Complete {
					t.Fatalf("scope=%t incorrect relationship: %+v", same, out)
				}
			}
		})
	}
	surface := bundle.Surface{Complete: true, Facts: []bundle.SurfaceFact{
		{Kind: "untrusted_input", Scope: "a", Source: report.SourceRef{Path: "a.sh", ByteEnd: 1}},
		{Kind: "command_execution", Scope: "b", Source: report.SourceRef{Path: "b.sh", ByteEnd: 1}},
		{Kind: "file_write", Scope: "c", Source: report.SourceRef{Path: "c.sh", ByteEnd: 1}},
	}}
	targets := []report.TargetResult{{ID: "root", State: report.RunComplete}}
	out := environment.Build(t.Context(), []bundle.Surface{surface}, targets, 1, 100)
	if out.Completeness != report.Partial || len(out.Observations) != 1 || !slices.Contains(out.Issues, "observation_limit") {
		t.Fatalf("capability observation cap hid omissions: %+v", out)
	}
	out = environment.Build(t.Context(), []bundle.Surface{surface}, targets, 10, 3)
	if out.Completeness != report.Partial || !slices.Contains(out.Issues, "operation_limit") {
		t.Fatalf("capability relation work exceeded its quota: %+v", out)
	}
}
