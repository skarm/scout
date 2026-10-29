package engine //nolint:testpackage // Exercises private coverage reduction and related-evidence admission.

import (
	"context"
	"testing"

	"github.com/skarm/scout/report"
)

func TestCoverageReducerUsesOutcomesWithoutDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*report.Analysis)
	}{
		{name: "inventory", alter: func(r *report.Analysis) { r.Artifact.InventoryComplete = false }},
		{name: "metadata", alter: func(r *report.Analysis) { r.Metadata.Completeness = report.Partial }},
		{name: "validation", alter: func(r *report.Analysis) { r.Validation.Completeness = report.Partial }},
		{
			name:  "extraction",
			alter: func(r *report.Analysis) { r.Extraction.Steps = []report.ExtractionStep{{Status: "partial"}} },
		},
		{
			name:  "signatures",
			alter: func(r *report.Analysis) { r.Signatures.Enabled = true; r.Signatures.Completeness = "partial" },
		},
		{
			name:  "semantic",
			alter: func(r *report.Analysis) { r.Semantic.Enabled = true; r.Semantic.Completeness = report.Partial },
		},
		{name: "vulnerabilities", alter: func(r *report.Analysis) {
			r.Vulnerabilities.Enabled = true
			r.Vulnerabilities.Completeness = report.Partial
		}},
		{name: "filecheck", alter: func(r *report.Analysis) { r.Coverage.Files[0].Checks[0].Status = "not_run" }},
		{name: "globalcheck", alter: func(r *report.Analysis) { r.Coverage.Checks[0].Status = "failed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := completeAnalysis()
			tc.alter(&r)
			reduceCoverage(context.Background(), &r)
			if r.Coverage.Completeness == report.Complete {
				t.Fatal("unfinished child reported complete without a diagnostic")
			}
		})
	}
}

func TestCoverageReducerDerivesFreshState(t *testing.T) {
	r := completeAnalysis()
	r.Coverage.Completeness = report.Partial
	r.Coverage.Files[0].Completeness = report.Partial
	reduceCoverage(context.Background(), &r)
	if r.Coverage.Completeness != report.Complete || r.Coverage.Files[0].Completeness != report.Complete {
		t.Fatal("stale independently set status remained authoritative")
	}
}

func completeAnalysis() report.Analysis {
	var r report.Analysis
	r.Artifact.InventoryComplete = true
	r.Metadata.Completeness = report.Complete
	r.Validation.Completeness = report.Complete
	r.Coverage.Files = []report.FileCoverage{{
		Path:       "input.txt",
		ReadStatus: "captured",
		Checks: []report.FileCheck{{
			AnalyzerID: "test",
			Status:     "completed",
		}},
	}}
	r.Coverage.Checks = []report.Check{{AnalyzerID: "test", Status: "completed"}}
	return r
}
