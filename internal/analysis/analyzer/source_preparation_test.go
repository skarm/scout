package analyzer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestSourceWalkerOperationLimitIsExplicit(t *testing.T) {
	text := strings.Repeat(":\n", 8192) + "NPM_CONFIG_REGISTRY=https://private.invalid\n"
	doc := document.Prepare(context.Background(), artifact.NewFile("input.sh", []byte(text), false))
	result, err := pluginRule(t, "NV-SC10").Find(context.Background(), prepared(context.Background(), doc), 16)
	if !result.Truncated && err == nil {
		t.Fatal("unvisited source tail reported as completed")
	}
}

func TestSourceWalkerSpendsSharedQuota(t *testing.T) {
	ctx := analysisbudget.WithLimit(context.Background(), 1)
	doc := document.Prepare(ctx, artifact.NewFile("input.sh", []byte("NPM_CONFIG_REGISTRY=https://private.invalid\nNPM_CONFIG_REGISTRY=https://other.invalid\n"), false))
	result, err := pluginRule(t, "NV-SC10").Find(ctx, prepared(ctx, doc), 16)
	if analysisbudget.Used(ctx) != 1 || !result.Truncated && err == nil {
		t.Fatalf("quota ignored: used=%d result=%+v err=%v", analysisbudget.Used(ctx), result, err)
	}
}

func TestSourceGeneratedConfigRequiresSelectedParser(t *testing.T) {
	text := "cat > .yarnrc.yml <<'EOF'\nnpmRegistryServer: https://private.invalid\nEOF\n"
	doc := document.Prepare(context.Background(), artifact.NewFile("input.sh", []byte(text), false))
	result, err := pluginRule(t, "NV-SC10").Find(context.Background(), prepared(context.Background(), doc), 16)
	if len(result.Matches) > 0 || !result.Truncated && err == nil {
		t.Fatalf("hidden YAML parser bypassed selected registry: %+v %v", result, err)
	}
}

func TestSourcePreparationUsesRunQuotaAndFreezesObservations(t *testing.T) {
	ctx := context.Background()
	files := []artifact.File{artifact.NewFile("input.sh", []byte("NPM_CONFIG_REGISTRY=https://private.invalid\nNPM_CONFIG_REGISTRY=https://other.invalid\n"), false)}
	checks := []analyzer.Analyzer{pluginRule(t, "NV-SC10")}
	// Two actors (the source prepass and its projection) share two operations;
	// the single admitted declaration cannot silently authorize the unvisited tail.
	docs, bound := analyzer.PrepareDerivedWithin(ctx, checks, document.PrepareAll(ctx, files), 16, 2)
	out, err := bound[0].Find(ctx, docs[0], 16)
	if err != nil || !out.Truncated || len(out.Matches) != 1 {
		t.Fatalf("source prepass quota was reset: %+v %v", out, err)
	}
	docs, bound = analyzer.PrepareDerivedWithin(ctx, checks, document.PrepareAll(ctx, files), 16, 100)
	projection := analysisbudget.WithLimit(ctx, 0)
	out, err = bound[0].Find(projection, document.Freeze(docs)[0], 16)
	if err != nil || out.Truncated || len(out.Matches) != 2 || analysisbudget.Used(projection) != 0 {
		t.Fatalf("projection reran source discovery: %+v %v", out, err)
	}
}
