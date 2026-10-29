package analyzer_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestPermissionEvidenceRetainsArchiveNamespace(t *testing.T) {
	ctx := context.Background()
	files := []artifact.File{
		artifact.NewFile("scout-object://one/plugin.json", []byte(`{"name":"one","permissions":["read"]}`), false),
		artifact.NewFile("scout-object://one/helper.go", []byte("package p\nfunc f(){os.Getenv(\"TOKEN\")}"), false),
		artifact.NewFile("scout-object://two/plugin.json", []byte(`{"name":"two","permissions":["environment"]}`), false),
		artifact.NewFile("scout-object://two/helper.go", []byte("package p\nfunc f(){os.Getenv(\"TOKEN\")}"), false),
	}
	docs := document.PrepareAll(ctx, files)
	extraction := report.ExtractionReport{Objects: []report.DerivedObject{
		{
			Role:       "archive_member",
			ParentPath: "one.zip",
			MemberName: ".claude-plugin/plugin.json",
			File:       files[0].Metadata(),
		},
		{Role: "archive_member", ParentPath: "one.zip", MemberName: "helper.go", File: files[1].Metadata()},
		{
			Role:       "archive_member",
			ParentPath: "two.tar",
			MemberName: ".claude-plugin/plugin.json",
			File:       files[2].Metadata(),
		},
		{Role: "archive_member", ParentPath: "two.tar", MemberName: "helper.go", File: files[3].Metadata()},
	}}
	checks := analyzer.BindContexts(ctx, []analyzer.Analyzer{pluginRule(t, "NV-LP1")}, docs, extraction)
	for _, index := range []int{0, 2} {
		result, err := checks[0].Find(ctx, docs[index], 10)
		if err != nil {
			t.Fatal(err)
		}
		if index == 2 {
			if len(result.Matches) != 0 {
				t.Fatal("permission declaration crossed the archive boundary", result)
			}
			continue
		}
		if len(result.Matches) != 1 || len(result.Matches[0].Related) != 1 {
			t.Fatal("missing scoped environment evidence", result)
		}
		ref := result.Matches[0].Related[0]
		if ref.Path != files[1].Metadata().Path || ref.SHA256 != files[1].Metadata().SHA256 {
			t.Fatal("evidence crossed the archive boundary", ref)
		}
		if got := artifact.Hash([]byte(files[1].Content()[ref.ByteStart:ref.ByteEnd])); got != ref.SpanSHA256 {
			t.Fatal("evidence lost its captured bytes", ref)
		}
	}
}

func TestPermissionDeclarationsRequireOwnedParsedConfig(t *testing.T) {
	for _, tc := range []struct{ name, declaration string }{
		{name: ".claude-plugin/plugin.json", declaration: `{"name":"broken","permissions":[`},
		{name: "SKILL.md", declaration: "# Documentation\n```json\n{\"permissions\":[\"*\"]}\n```\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			docs := document.PrepareAll(ctx, []artifact.File{
				artifact.NewFile(tc.name, []byte(tc.declaration), false),
				artifact.NewFile("helper.go", []byte("package p\nfunc f(){os.Getenv(\"TOKEN\")}"), false),
			})
			checks := analyzer.BindContexts(ctx, []analyzer.Analyzer{pluginRule(t, "NV-LP2"), pluginRule(t, "NV-LP3")}, docs, report.ExtractionReport{})
			for _, check := range checks {
				if check.AppliesTo(docs[0]) {
					t.Fatal("unparsed or example content created a permission scope", check.Rule().ID)
				}
				result, err := check.Find(ctx, docs[0], 10)
				if err != nil || len(result.Matches) != 0 || result.Truncated {
					t.Fatal("unparsed or example content supplied a permission declaration", result, err)
				}
			}
		})
	}
}
