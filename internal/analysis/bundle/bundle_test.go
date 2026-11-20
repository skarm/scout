package bundle_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestBundleFindReturnsIndependentEvidence(t *testing.T) {
	manifest := artifact.NewFile("package.json", []byte(`{"scripts":{"prepare":"node helper.js"}}`), false)
	helper := artifact.NewFile("helper.js", []byte("// Fixture\n"), false)
	docs := document.PrepareAll(t.Context(), []artifact.File{manifest, helper})
	analyzer := boundBundleRule(t, "SC004", docs)
	first, err := analyzer.Find(t.Context(), docs[0], 1)
	if err != nil || first.Truncated || len(first.Matches) != 1 || len(first.Matches[0].Related) != 1 {
		t.Fatalf("fixture lost bounded install evidence: %+v, %v", first, err)
	}
	start, evidence := first.Matches[0].Start, first.Matches[0].Related[0]
	if evidence.Path != "helper.js" || evidence.SpanSHA256 != helper.Metadata().SHA256 {
		t.Fatalf("unexpected helper evidence: %+v", evidence)
	}
	first.Matches[0].Start = -1
	first.Matches[0].Related[0].Path = "mutated"

	second, err := analyzer.Find(t.Context(), docs[0], 1)
	if err != nil || second.Truncated || len(second.Matches) != 1 || second.Matches[0].Start != start ||
		len(second.Matches[0].Related) != 1 || second.Matches[0].Related[0] != evidence {
		t.Fatalf("a previous projection mutated bound observations: %+v, %v", second, err)
	}
}

func TestEmptySupportingFileKeepsPrimaryBundleEvidence(t *testing.T) {
	for _, tc := range []struct{ name, rule, source, text, supporting string }{
		{"install", "SC004", "package.json", `{"scripts":{"prepare":"node helper.js"}}`, "helper.js"},
		{"http", "NET001", "sample.go", `package sample; import "net/http"; func fetch() { http.Get("https://example.invalid") }`, "SKILL.md"},
		{"dns", "NET001", "sample.go", `package sample; import "net"; func lookup() { net.LookupHost("example.invalid") }`, "SKILL.md"},
	} {
		for _, support := range []struct{ name, text string }{{"empty", ""}, {"nonempty", "Fixture documentation."}} {
			t.Run(tc.name+"/"+support.name, func(t *testing.T) {
				file := artifact.NewFile(tc.source, []byte(tc.text), false)
				other := artifact.NewFile(tc.supporting, []byte(support.text), false)
				docs := document.PrepareAll(t.Context(), []artifact.File{file, other})
				got, err := boundBundleRule(t, tc.rule, docs).Find(t.Context(), docs[0], 1)
				if err != nil || got.Truncated || len(got.Matches) != 1 || got.Matches[0].Start >= got.Matches[0].End {
					t.Fatalf("primary evidence lost or reported incomplete: %+v, err=%v", got, err)
				}
				refs := got.Matches[0].Related
				if support.text == "" && len(refs) != 0 {
					t.Fatalf("empty file yielded an invalid span: %+v", refs)
				}
				if support.text != "" && (len(refs) != 1 || refs[0].Path != tc.supporting || refs[0].SpanSHA256 != other.Metadata().SHA256) {
					t.Fatalf("nonempty supporting evidence was lost: %+v", refs)
				}
			})
		}
	}
}

func boundBundleRule(t *testing.T, id string, docs []document.File) check.Analyzer {
	t.Helper()
	for _, rule := range bundle.Bind(t.Context(), bundle.Rules(), docs, report.ExtractionReport{}, 4) {
		if rule.Rule().ID == id {
			return rule
		}
	}
	t.Fatalf("bundle catalog lost %s", id)
	return nil
}
