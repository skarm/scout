package engine //nolint:testpackage // Exercises private coverage reduction and related-evidence admission.

import (
	"context"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestClassificationCoveragePreservesGapPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, content, category string
		extracted               bool
		gaps                    []string
	}{
		{name: "plain.txt", content: "ordinary notes", category: "text", extracted: false, gaps: []string{}},
		{
			name:      "unknown",
			content:   "ordinary notes",
			category:  "unknown",
			extracted: false,
			gaps:      []string{"unrecognized_content"},
		},
		{name: "opaque", content: "\x00", category: "unknown", extracted: false, gaps: []string{"opaque_content"}},
		{
			name:      "app",
			content:   "\x7fELF\x00",
			category:  "executable",
			extracted: false,
			gaps:      []string{"opaque_content"},
		},
		{
			name:      "script.rb",
			content:   "puts 'hi'",
			category:  "source-or-config",
			extracted: false,
			gaps:      []string{"structural_analysis_unavailable"},
		},
		{
			name:      "package.zip",
			content:   "PK\x03\x04\x00",
			category:  "archive",
			extracted: false,
			gaps:      []string{"nested_archive_unsupported"},
		},
		{
			name:      "package.zip",
			content:   "PK\x03\x04\x00",
			category:  "archive",
			extracted: true,
			gaps:      []string{"container_semantics_limited"},
		},
		{
			name:      "image.png",
			content:   "\x89PNG\r\n\x1a\n",
			category:  "image",
			extracted: false,
			gaps:      []string{"container_semantics_unavailable"},
		},
		{
			name:      "image.png",
			content:   "\x89PNG\r\n\x1a\n",
			category:  "image",
			extracted: true,
			gaps:      []string{"container_semantics_limited"},
		},
		{
			name:      "document.pdf",
			content:   "%PDF-1.7\n",
			category:  "document",
			extracted: false,
			gaps:      []string{"container_semantics_unavailable"},
		},
		{
			name:      "document.pdf",
			content:   "%PDF-1.7\n",
			category:  "document",
			extracted: true,
			gaps:      []string{"container_semantics_limited"},
		},
		{
			name:      "data.sqlite",
			content:   "SQLite format 3\x00",
			category:  "database",
			extracted: false,
			gaps:      []string{"container_semantics_unavailable"},
		},
		{
			name:      "data.sqlite",
			content:   "SQLite format 3\x00",
			category:  "database",
			extracted: true,
			gaps:      []string{"container_semantics_limited"},
		},
		{
			name:      "audio.mp3",
			content:   "\x00",
			category:  "media",
			extracted: false,
			gaps:      []string{"container_semantics_unavailable"},
		},
		{
			name:      "audio.mp3",
			content:   "\x00",
			category:  "media",
			extracted: true,
			gaps:      []string{"container_semantics_limited"},
		},
		{
			name:      "disguised.txt",
			content:   "\x89PNG\r\n\x1a\n",
			category:  "image",
			extracted: true,
			gaps:      []string{"container_semantics_limited", "conflicting_content_hints"},
		},
	} {
		t.Run(tc.name+"/"+map[bool]string{true: "extracted", false: "raw"}[tc.extracted], func(t *testing.T) {
			file := artifact.NewFile(tc.name, []byte(tc.content), false)
			doc := document.Prepare(context.Background(), file)
			var analysis report.Analysis
			coverage := report.FileCoverage{Path: tc.name, Gaps: []string{}}
			classifyCoverage(&analysis, &coverage, doc, map[string]bool{tc.name: tc.extracted})
			if coverage.Classification.Category != tc.category || !reflect.DeepEqual(coverage.Gaps, tc.gaps) {
				t.Fatalf("classification=%+v gaps=%v, want %s %v", coverage.Classification, coverage.Gaps, tc.category, tc.gaps)
			}
			var scopeCodes []string
			for _, diagnostic := range analysis.Diagnostics {
				if diagnostic.Path != tc.name || diagnostic.Message == "" {
					t.Fatalf("diagnostic lost source or explanation: %+v", diagnostic)
				}
				if diagnostic.AffectsScope {
					scopeCodes = append(scopeCodes, diagnostic.Code)
				}
			}
			if len(scopeCodes) != len(tc.gaps) {
				t.Fatalf("gaps were dropped or duplicated in diagnostics: %v", scopeCodes)
			}
			if len(scopeCodes) > 0 && !reflect.DeepEqual(scopeCodes, tc.gaps) {
				t.Fatalf("diagnostic order changed: %v", scopeCodes)
			}
			if (analysis.Coverage.TextFiles == 1) != (file.Metadata().Kind == "text") {
				t.Fatal("text count changed with classification")
			}
		})
	}
}

func TestClassificationCoverageRetainsPreparedUnitsAndDiagnostics(t *testing.T) {
	file := artifact.NewFile("main.go", []byte("package main\nfunc main() {}\n"), false)
	doc := document.Prepare(context.Background(), file)
	var analysis report.Analysis
	coverage := report.FileCoverage{Path: "main.go"}
	classifyCoverage(&analysis, &coverage, doc, nil)
	if len(coverage.Units) != 1 || coverage.Units[0].Language != "go" || coverage.Units[0].ByteEnd != len(file.Content()) || coverage.Units[0].ParserID == "" {
		t.Fatalf("prepared unit metadata lost: %+v", coverage.Units)
	}
	if !reflect.DeepEqual(analysis.Diagnostics, doc.Diagnostics()) || len(coverage.Gaps) != 0 {
		t.Fatal("advisory preparation diagnostics were lost or turned into gaps")
	}
}
