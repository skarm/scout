package analyzer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestPrepareGeneratedShellUsesOneQuotaAcrossDocuments(t *testing.T) {
	const input = "cat > helper.sh <<'END'\necho ok\nEND\n"
	files := []artifact.File{
		artifact.NewFile("first.sh", []byte(input), false),
		artifact.NewFile("second.sh", []byte(input), false),
	}
	docs := document.PrepareAll(t.Context(), files)
	skipped := analyzer.PrepareGeneratedShellWithin(t.Context(), nil, docs, 0)
	if len(skipped[0].Units()) != 1 || len(skipped[1].Units()) != 1 {
		t.Fatal("script prepared with no shell consumers selected")
	}

	checks := shell.Rules()[:1]
	operations := uint64(analyzer.OperationTasks(checks))
	prepared := analyzer.PrepareGeneratedShellWithin(t.Context(), checks, docs, operations)
	first, second := prepared[0].Units(), prepared[1].Units()
	if len(first) != 2 || first[1].Origin != "heredoc" || first[1].View.Text() != "echo ok\n" || len(second) != 1 || len(docs[0].Units()) != 1 {
		t.Fatalf("shared quota or original document lost: first=%+v second=%+v", first, second)
	}
	for _, diagnostic := range prepared[1].Diagnostics() {
		if diagnostic.Code == "generated_shell_incomplete" && diagnostic.AffectsScope && diagnostic.Path == "second.sh" {
			return
		}
	}
	t.Fatalf("second script exceeded quota without a scoped diagnostic: %+v", prepared[1].Diagnostics())
}

func TestPrepareGeneratedShellReportsNestedWriteGapOnCapturedFile(t *testing.T) {
	const path = "setup.sh"
	const inner = "cat >>\"${name}.sh\" <<'INNER'\nprintf example\nINNER\n"
	const input = "cat > outer.sh <<'OUTER'\n" + inner + "OUTER\n"
	doc := document.Prepare(t.Context(), artifact.NewFile(path, []byte(input), false))
	prepared := analyzer.PrepareGeneratedShellWithin(t.Context(), shell.Rules()[:1], []document.File{doc}, 100)[0]
	units := prepared.Units()
	if len(units) != 2 || units[1].Origin != document.OriginGeneratedShell || units[1].View.Text() != inner {
		t.Fatalf("unexpected generated units: %+v", units)
	}

	want := map[string]bool{"generated_shell_append": true, "generated_shell_dynamic_path": true}
	for _, diagnostic := range prepared.Diagnostics() {
		if !strings.HasPrefix(diagnostic.Code, "generated_shell_") {
			continue
		}

		if !want[diagnostic.Code] || diagnostic.Path != path || !diagnostic.AffectsScope {
			t.Fatalf("unexpected generated diagnostic: %+v", diagnostic)
		}
		delete(want, diagnostic.Code)
	}
	if len(want) != 0 {
		t.Fatalf("missing nested diagnostics: %v", want)
	}
}

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
