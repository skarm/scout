package report_test

import (
	"reflect"
	"testing"

	"github.com/skarm/scout/report"
)

func TestAnalysisCannotCarryAdmissionOpinions(t *testing.T) {
	shape := reflect.TypeFor[report.Analysis]()
	for _, name := range []string{"Policy", "Baseline", "Risk"} {
		if _, ok := shape.FieldByName(name); ok {
			t.Fatalf("analysis carries operator opinion %s", name)
		}
	}
}

func TestDependencyManifestInventoryCompletion(t *testing.T) {
	for _, tc := range []struct {
		status   string
		complete bool
	}{
		{status: "completed", complete: true},
		{status: "parsed_limited", complete: true},
		{status: "partial", complete: false},
		{status: "cancelled", complete: false},
		{status: "failed", complete: false},
		{status: "unsupported", complete: false},
		{status: "evidence_mapping_failed", complete: false},
		{status: "future_status", complete: false},
		{status: "", complete: false},
	} {
		t.Run(tc.status, func(t *testing.T) {
			manifest := report.DependencyManifest{Status: tc.status}
			if got := manifest.InventoryComplete(); got != tc.complete {
				t.Fatalf("inventory complete=%v, want %v", got, tc.complete)
			}
		})
	}
}

func TestLimitsValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*report.CaptureLimits)
	}{
		{name: "entries", change: func(l *report.CaptureLimits) { l.MaxEntries = 0 }},
		{name: "files", change: func(l *report.CaptureLimits) { l.MaxFiles = l.MaxEntries + 1 }},
		{name: "filebytes", change: func(l *report.CaptureLimits) { l.MaxFileBytes = -1 }},
		{name: "totalbytes", change: func(l *report.CaptureLimits) { l.MaxTotalBytes = 1 }},
		{name: "archivebytes", change: func(l *report.CaptureLimits) { l.MaxArchiveBytes = 0 }},
		{name: "pathbytes", change: func(l *report.CaptureLimits) { l.MaxPathBytes = 5000 }},
		{name: "depth", change: func(l *report.CaptureLimits) { l.MaxDepth = 0 }},
		{name: "findings", change: func(l *report.CaptureLimits) { l.MaxFindings = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := report.DefaultCaptureLimits()
			tc.change(&l)
			if l.Validate() == nil {
				t.Fatal("invalid limits accepted")
			}
		})
	}
	if err := report.DefaultCaptureLimits().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionLimitsValidation(t *testing.T) {
	if err := report.DefaultExtractionLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*report.ExtractionLimits)
	}{
		{name: "depth-low", edit: func(l *report.ExtractionLimits) { l.MaxDepth = 0 }},
		{name: "depth-high", edit: func(l *report.ExtractionLimits) { l.MaxDepth = 17 }},
		{name: "objects-low", edit: func(l *report.ExtractionLimits) { l.MaxObjects = 0 }},
		{name: "objects-high", edit: func(l *report.ExtractionLimits) { l.MaxObjects = 4097 }},
		{name: "entries-low", edit: func(l *report.ExtractionLimits) { l.MaxEntries = 0 }},
		{name: "entries-high", edit: func(l *report.ExtractionLimits) { l.MaxEntries = 100001 }},
		{name: "object-low", edit: func(l *report.ExtractionLimits) { l.MaxObjectBytes = 0 }},
		{name: "object-high", edit: func(l *report.ExtractionLimits) { l.MaxObjectBytes = 33 << 20 }},
		{name: "total-low", edit: func(l *report.ExtractionLimits) { l.MaxTotalBytes = 1 }},
		{name: "total-high", edit: func(l *report.ExtractionLimits) { l.MaxTotalBytes = 129 << 20 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := report.DefaultExtractionLimits()
			tc.edit(&l)
			if l.Validate() == nil {
				t.Fatal("invalid limits accepted")
			}
		})
	}
}
