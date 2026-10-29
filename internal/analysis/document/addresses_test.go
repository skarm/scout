package document_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestCapturedAddressesPreserveNamespaceAndObjectRole(t *testing.T) {
	names := []string{"README.md", "scout-object://decoded", "scout-object://metadata", "scout-object://one", "scout-object://two", "scout-object://future", "scout-object://unclaimed"}
	files := make([]artifact.File, 0, len(names))
	for _, name := range names {
		files = append(files, artifact.NewFile(name, []byte("captured bytes"), false))
	}
	docs := document.PrepareAll(context.Background(), files)
	extraction := report.ExtractionReport{Objects: []report.DerivedObject{
		{
			Role:        "decoded",
			ExtractorID: "json-strings",
			ParentPath:  "snapshot.json",
			MemberName:  ".claude/settings.json",
			File:        report.File{Path: "scout-object://decoded"},
		},
		{
			Role:        "metadata",
			ExtractorID: "zip32",
			ParentPath:  "one.zip",
			MemberName:  ".claude/settings.json",
			File:        report.File{Path: "scout-object://metadata"},
		},
		{
			Role:        "archive_member",
			ExtractorID: "zip32",
			ParentPath:  "one.zip",
			MemberName:  "hooks/hooks.json",
			File:        report.File{Path: "scout-object://one"},
		},
		{
			Role:        "archive_member",
			ExtractorID: "tar",
			ParentPath:  "two.tar",
			MemberName:  "hooks/hooks.json",
			File:        report.File{Path: "scout-object://two"},
		},
		{
			Role:        "archive_member",
			ExtractorID: "future-format",
			ParentPath:  "future.container",
			MemberName:  "hooks/hooks.json",
			File:        report.File{Path: "scout-object://future"},
		},
		{
			Role:        "archive_member",
			ExtractorID: "zip32",
			ParentPath:  "one.zip",
			MemberName:  "unread.json",
			File:        report.File{Path: "scout-object://unread"},
		},
	}}
	want := map[string]document.Address{
		"README.md":             {Namespace: "snapshot", Name: "README.md"},
		"scout-object://one":    {Namespace: "one.zip", Name: "hooks/hooks.json"},
		"scout-object://two":    {Namespace: "two.tar", Name: "hooks/hooks.json"},
		"scout-object://future": {Namespace: "future.container", Name: "hooks/hooks.json"},
		"scout-object://unread": {Namespace: "one.zip", Name: "unread.json"},
	}
	actual := document.CapturedAddresses(docs, extraction)
	if !reflect.DeepEqual(actual, want) {
		t.Fatal(actual)
	}
	actual["README.md"] = document.Address{}
	delete(actual, "scout-object://one")
	if next := document.CapturedAddresses(docs, extraction); !reflect.DeepEqual(next, want) {
		t.Fatal("address map escaped its scan", next)
	}
}

func TestCapturedAddressesRetainRecordedSpellingAndDeclarationPrecedence(t *testing.T) {
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("captured.json", []byte("{}"), false)})
	extraction := report.ExtractionReport{Objects: []report.DerivedObject{
		{
			Role:       "archive_member",
			ParentPath: "first.zip",
			MemberName: "first.json",
			File:       report.File{Path: "captured.json"},
		},
		{
			Role:       "archive_member",
			ParentPath: "outer//container.tar",
			MemberName: "./nested//last.json",
			File:       report.File{Path: "captured.json"},
		},
	}}
	addresses := document.CapturedAddresses(docs, extraction)
	if got := addresses["captured.json"]; got.Namespace != "outer//container.tar" || got.Name != "./nested//last.json" {
		t.Fatal(got)
	}
	if empty := document.CapturedAddresses(nil, report.ExtractionReport{}); empty == nil || len(empty) != 0 {
		t.Fatal(empty)
	}
}
