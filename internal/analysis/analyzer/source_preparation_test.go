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

		if !want[diagnostic.Code] || diagnostic.Path != path || !diagnostic.AffectsScope || diagnostic.Line != 2 || diagnostic.Column != 1 {
			t.Fatalf("unexpected generated diagnostic: %+v", diagnostic)
		}
		delete(want, diagnostic.Code)
	}
	if len(want) != 0 {
		t.Fatalf("missing nested diagnostics: %v", want)
	}
}

func TestPrepareGeneratedShellLocatesGapsAndDistinguishesReasons(t *testing.T) {
	const input = "  ```bash\n  cat > first.sh <<END\n  printf '%s' \"$unknown\"\n  END\n" +
		"  PATH=/custom/bin\n  cat > second.sh <<'END'\n  printf ok\n  END\n  ```\n"
	doc := document.Prepare(t.Context(), artifact.NewFile("README.md", []byte(input), false))
	prepared := analyzer.PrepareGeneratedShellWithin(t.Context(), shell.Rules()[:1], []document.File{doc}, 100)[0]
	want := map[int]document.GeneratedShellReason{2: document.GeneratedShellExpansion, 6: document.GeneratedShellWriter}
	for _, diagnostic := range prepared.Diagnostics() {
		if diagnostic.Code != "generated_shell_incomplete" {
			continue
		}

		if reason, ok := want[diagnostic.Line]; !ok || diagnostic.Column != 3 || diagnostic.Path != "README.md" || diagnostic.Message != string(reason) {
			t.Fatalf("unexpected diagnostic: %+v", diagnostic)
		}

		delete(want, diagnostic.Line)
	}

	if len(want) != 0 {
		t.Fatalf("missing located diagnostics: %v", want)
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

func TestSourceDeclarationRetentionLimitIsPreserved(t *testing.T) {
	ctx := t.Context()
	text := "NPM_CONFIG_REGISTRY=https://first.invalid\nNPM_CONFIG_REGISTRY=https://second.invalid\n"
	doc := document.Prepare(ctx, artifact.NewFile("input.sh", []byte(text), false))
	check := pluginRule(t, "NV-SC10")
	docs, bound := analyzer.PrepareDerivedWithin(ctx, []analyzer.Analyzer{check}, []document.File{doc}, 10, 0)
	for _, tc := range []struct {
		name  string
		check analyzer.Analyzer
		doc   document.File
	}{{"unbound", check, doc}, {"bound", bound[0], docs[0]}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, budget := range []int{0, 1, 2} {
				result, err := tc.check.Find(ctx, tc.doc, budget)
				if err != nil || len(result.Matches) != budget || result.Truncated != (budget < 2) {
					t.Fatalf("budget %d lost retention state: %+v %v", budget, result, err)
				}
			}
		})
	}
}

func TestDerivedConfigurationLimitCountsDistinctInputs(t *testing.T) {
	const one = "cat > .npmrc <<'END'\ncolor=true\nEND\n"
	for _, tc := range []struct {
		name, last string
		gap        bool
	}{
		{"exact", one, false},
		{"duplicate at capacity", "tee .npmrc .npmrc <<'END'\ncolor=true\nEND\n", false},
		{"additional file", "tee .npmrc pip.ini <<'END'\ncolor=true\nEND\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Repeat(one, document.MaxRegions-1) + tc.last
			doc := document.Prepare(t.Context(), artifact.NewFile("setup.sh", []byte(text), false))
			prepared := prepareDerived(t.Context(), []document.File{doc})[0]
			children, limited := prepared.DerivedConfigs()
			if len(children) != document.MaxRegions || limited != tc.gap {
				t.Fatalf("retained %d configurations, limited=%v; want %d, %v", len(children), limited, document.MaxRegions, tc.gap)
			}
			for i, child := range children {
				if child.File == nil || child.File.Artifact().Metadata().Path != ".npmrc" || i > 0 && child.Span.Start <= children[i-1].Span.Start {
					t.Fatalf("unexpected configuration at %d", i)
				}
			}
		})
	}
}

func TestMavenSourceURLUsesCompleteElementText(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		count       int
		partial     bool
	}{
		{"plain-default", "https://repo.maven.apache.org/maven2", 0, false},
		{"cdata-default", "https://repo.maven.<![CDATA[apache.org]]>/maven2", 0, false},
		{"comment-default", "https://repo.maven.<!-- boundary -->apache.org/maven2", 0, false},
		{"entity-default", "https://repo.maven.apache.org&#47;maven2", 0, false},
		{"cdata-private", "https://private.<![CDATA[example.invalid]]>/maven2", 1, false},
		{"empty", "", 0, false},
		{"nested-markup", "https://private.<host>example.invalid</host>/maven2", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "<project><repositories><repository><url>" + tc.value + "</url></repository></repositories></project>"
			doc := document.Prepare(t.Context(), artifact.NewFile("pom.xml", []byte(text), false))
			result, err := pluginRule(t, "NV-SC10").Find(t.Context(), doc, 10)
			if err != nil || result.Truncated != tc.partial || len(result.Matches) != tc.count {
				t.Fatalf("complete URL classification changed: %+v %v", result, err)
			}
			for _, match := range result.Matches {
				if got := text[match.Start:match.End]; got != tc.value {
					t.Fatalf("URL evidence %q, want original content %q", got, tc.value)
				}
			}
		})
	}
}

func TestSourceConfigUsesCapturedBasename(t *testing.T) {
	const text = "index-url=https://packages.example.invalid/simple\n"
	for _, tc := range []struct {
		name string
		want int
	}{
		{name: "docs/pip.conf", want: 1},
		{name: "docs/%70ip.conf"},
		{name: "docs/notes%2Fpip.conf"},
		{name: "scout-object://fixture/pip.conf", want: 1},
		{name: "scout-object://fixture/%2570ip.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSourceLineMatches(t, tc.name, text, tc.want)
		})
	}
}

func TestNpmrcSourceUsesQuotedAssignmentValues(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       int
	}{
		{name: "default", text: "registry=https://registry.npmjs.org/"},
		{name: "quoted default", text: `registry="https://registry.npmjs.org/"`},
		{name: "quoted scoped default", text: "@fixture:registry='https://registry.npmjs.org/'"},
		{name: "quoted scoped alternate", text: `@fixture:registry="https://packages.example.invalid/"`, want: 1},
		{name: "quoted alternate", text: "registry='https://packages.example.invalid/'", want: 1},
		{name: "unbalanced quote", text: `registry="https://registry.npmjs.org/`, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSourceLineMatches(t, ".npmrc", tc.text+"\n", tc.want)
		})
	}
}

func assertSourceLineMatches(t *testing.T, name, text string, want int) {
	t.Helper()
	doc := document.Prepare(t.Context(), artifact.NewFile(name, []byte(text), false))
	result, err := pluginRule(t, "NV-SC10").Find(t.Context(), doc, 1)
	if err != nil || result.Truncated || len(result.Matches) != want {
		t.Fatalf("want %d source observations, got %+v, err=%v", want, result, err)
	}
	for _, match := range result.Matches {
		if match.Start != 0 || match.End != len(text) {
			t.Fatalf("invalid source span %+v", match)
		}
	}
}
