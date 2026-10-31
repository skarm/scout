package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/skarm/scout/report"
)

func TestRunDigestIgnoresAcquisitionAndCompletionOrder(t *testing.T) {
	a, err := report.SealRun(runFixture())
	if err != nil {
		t.Fatal(err)
	}
	b := runFixture()
	b.Targets[0].Label = "/different/workspace"
	b.Targets[0].Analysis.Source = &report.SourceProvenance{
		Kind:              "remote",
		TargetSHA256:      "different",
		DownloadURLSHA256: "elsewhere",
	}
	b.Targets[0].Analysis.Vulnerabilities.QueriedAt = "2030-01-01T00:00:00Z"
	slices.Reverse(b.Targets[0].Analysis.Findings)
	slices.Reverse(b.Targets[0].Analysis.Diagnostics)
	slices.Reverse(b.Plan.Checks)
	b, err = report.SealRun(b)
	if err != nil || a.Digest != b.Digest {
		t.Fatalf("display/acquisition/order changed stable result: %q %q %v", a.Digest, b.Digest, err)
	}
	if b.Targets[0].Label != "/different/workspace" || b.Targets[0].Analysis.Source == nil || b.Targets[0].Analysis.Vulnerabilities.QueriedAt == "" {
		t.Fatal("sealing discarded display or acquisition metadata")
	}
}

func TestRunDigestBindsStableEvidenceAndTraceOrder(t *testing.T) {
	a, err := report.SealRun(runFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*report.Run)
	}{
		{name: "rulepack", change: func(r *report.Run) { r.Engine.RulepackDigest = "changed" }},
		{name: "snapshot", change: func(r *report.Run) { r.Targets[0].Analysis.Artifact.SnapshotSHA256 = "changed" }},
		{name: "severity", change: func(r *report.Run) { r.Targets[0].Analysis.Findings[0].Severity = report.Critical }},
		{
			name:   "evidence",
			change: func(r *report.Run) { r.Targets[0].Analysis.Findings[0].Evidence.SpanSHA256 = "changed" },
		},
		{name: "plan", change: func(r *report.Run) { r.Plan.Checks[0].Selected = false }},
		{name: "trace-order", change: func(r *report.Run) { slices.Reverse(r.Targets[0].Analysis.Findings[0].Trace) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runFixture()
			tc.change(&r)
			b, err := report.SealRun(r)
			if err != nil || a.Digest == b.Digest {
				t.Fatalf("change not bound to digest: %q %q %v", a.Digest, b.Digest, err)
			}
		})
	}
}

func TestRunSealingOwnsItsDataAndDoesNotMutateInput(t *testing.T) {
	input := runFixture()
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := report.SealRun(input)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("sealing modified caller: %s %s %v", before, after, err)
	}
	sealed.Targets[0].Analysis.Findings[0].Trace[0].Role = "modified"
	sealed.Plan.Checks[0].ID = "modified"
	if input.Targets[0].Analysis.Findings[0].Trace[0].Role == "modified" || input.Plan.Checks[0].ID == "modified" {
		t.Fatal("sealed result aliases caller slices")
	}
}

func TestRunRejectsInvalidPlanAndFalseCompletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*report.Run)
	}{
		{name: "unknown-state", change: func(r *report.Run) { r.State = report.Unknown }},
		{name: "unknown-operation", change: func(r *report.Run) { r.Operation = "invented" }},
		{name: "empty", change: func(r *report.Run) { r.Targets = nil }},
		{name: "bad-index", change: func(r *report.Run) { r.Targets[0].Index = 1 }},
		{
			name:   "duplicate-target",
			change: func(r *report.Run) { r.Targets = append(r.Targets, r.Targets[0]); r.Targets[1].Index = 1 },
		},
		{name: "unknown-target", change: func(r *report.Run) { r.Targets[0].State = report.Unknown }},
		{name: "incomplete-target", change: func(r *report.Run) { r.Targets[0].State = report.RunIncomplete }},
		{
			name:   "incomplete-coverage",
			change: func(r *report.Run) { r.Targets[0].Analysis.Coverage.Completeness = report.Partial },
		},
		{name: "unknown-coverage", change: func(r *report.Run) { r.Targets[0].Analysis.Coverage.Completeness = "" }},
		{
			name:   "affecting-diagnostic",
			change: func(r *report.Run) { r.Targets[0].Analysis.Diagnostics[0].AffectsScope = true },
		},
		{
			name:   "incomplete-file",
			change: func(r *report.Run) { r.Targets[0].Analysis.Coverage.Files[0].Completeness = report.Partial },
		},
		{
			name:   "incomplete-check",
			change: func(r *report.Run) { r.Targets[0].Analysis.Coverage.Checks[0].Status = "failed" },
		},
		{
			name:   "missing-result",
			change: func(r *report.Run) { r.Targets[0].Analysis.Validation.Completeness = report.Partial },
		},
		{name: "incomplete-native", change: func(r *report.Run) {
			r.Targets[0].Analysis.Signatures = report.SignatureReport{Enabled: true, Completeness: "partial"}
		}},
		{name: "incomplete-dependencies", change: func(r *report.Run) {
			r.Targets[0].Analysis.Dependencies.Manifests = []report.DependencyManifest{{Path: "go.mod", Status: report.OutcomePartial}}
		}},
		{name: "truncated-native", change: func(r *report.Run) {
			r.Targets[0].Analysis.Signatures = report.SignatureReport{
				Enabled:      true,
				Completeness: "complete",
				Outcomes: []report.SignatureOutcome{{
					Status:    "completed",
					Truncated: true,
				}},
			}
		}},
		{
			name: "problem",
			change: func(r *report.Run) {
				r.Problems = []report.Problem{{
					Code:  "capture_failed",
					Phase: "capture",
				}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runFixture()
			tc.change(&r)
			if _, err := report.SealRun(r); err == nil {
				t.Fatalf("invalid or incomplete work accepted as complete: %+v", r)
			}
		})
	}
}

func TestRunRequiresEverySemanticTaskToComplete(t *testing.T) {
	for _, status := range []string{"", "failed", "not_run", "cancelled", "partial", "invented", "not_applicable", "cached", "disabled"} {
		t.Run("status-"+status, func(t *testing.T) {
			r := semanticRunFixture()
			r.Targets[0].Analysis.Semantic.Outcomes[0].Status = status
			if _, err := report.SealRun(r); err == nil {
				t.Fatalf("unfinished semantic task accepted as complete: %q", status)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*report.SemanticReport)
	}{
		{name: "incomplete-review", change: func(s *report.SemanticReport) { s.Completeness = report.Partial }},
		{
			name:   "review-gap",
			change: func(s *report.SemanticReport) { s.Gaps = []report.SemanticGap{{Code: "missing_context"}} },
		},
		{name: "omitted-review-gap", change: func(s *report.SemanticReport) { s.OmittedGaps = 1 }},
		{name: "missing-outcome", change: func(s *report.SemanticReport) { s.Outcomes = s.Outcomes[:1] }},
		{name: "missing-outcome-with-matching-count", change: func(s *report.SemanticReport) {
			s.Outcomes = s.Outcomes[:1]
			s.CompletedRequests = len(s.Outcomes)
		}},
		{name: "unknown-outcome", change: func(s *report.SemanticReport) { s.Outcomes[0].TaskID = "unknown" }},
		{name: "duplicate-outcome", change: func(s *report.SemanticReport) { s.Outcomes[0] = s.Outcomes[1] }},
		{name: "empty-task-id", change: func(s *report.SemanticReport) { s.Tasks[0].ID = "" }},
		{name: "duplicate-task", change: func(s *report.SemanticReport) { s.Tasks[0] = s.Tasks[1] }},
		{name: "unplanned-outcome", change: func(s *report.SemanticReport) { s.Tasks = nil }},
		{name: "missing-completed-request", change: func(s *report.SemanticReport) { s.CompletedRequests-- }},
		{name: "extra-completed-request", change: func(s *report.SemanticReport) { s.CompletedRequests++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := semanticRunFixture()
			tc.change(&r.Targets[0].Analysis.Semantic)
			if _, err := report.SealRun(r); err == nil {
				t.Fatal("inconsistent semantic task plan accepted as complete")
			}
		})
	}
}

func TestRunAcceptsCompletedSemanticPlansAndRetainsPartialEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*report.Run)
	}{
		{name: "complete", change: func(*report.Run) {}},
		{
			name:   "completion-order",
			change: func(r *report.Run) { slices.Reverse(r.Targets[0].Analysis.Semantic.Outcomes) },
		},
		{name: "empty-plan", change: func(r *report.Run) {
			r.Targets[0].Analysis.Semantic = report.SemanticReport{Enabled: true, Completeness: report.Complete}
		}},
		{name: "disabled-service", change: func(r *report.Run) {
			s := &r.Targets[0].Analysis.Semantic
			s.Enabled, s.Outcomes[0].Status = false, "not_run"
		}},
		{name: "partial-target", change: func(r *report.Run) {
			r.State, r.Targets[0].State = report.RunIncomplete, report.RunIncomplete
			s := &r.Targets[0].Analysis.Semantic
			s.Completeness, s.Outcomes[0].Status = report.Partial, "failed"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := semanticRunFixture()
			tc.change(&r)
			sealed, err := report.SealRun(r)
			if err != nil {
				t.Fatalf("valid task plan or partial evidence rejected: %v", err)
			}
			if len(sealed.Targets[0].Analysis.Findings) != len(r.Targets[0].Analysis.Findings) {
				t.Fatal("semantic validation discarded static evidence")
			}
		})
	}
}

func TestRunRejectsFalseTaskValidationCompletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*report.ValidationReport)
	}{
		{name: "omitted-tasks", change: func(v *report.ValidationReport) { v.OmittedTasks = 1 }},
		{name: "plan-issue", change: func(v *report.ValidationReport) { v.Issues = []string{"missing_task"} }},
		{name: "failed-required", change: func(v *report.ValidationReport) { v.Outcomes[0].Status = "failed" }},
		{name: "failed-optional", change: func(v *report.ValidationReport) { v.Outcomes[1].Status = "failed" }},
		{name: "disabled-required", change: func(v *report.ValidationReport) { v.Outcomes[0].Status = "disabled" }},
		{name: "missing-outcome", change: func(v *report.ValidationReport) { v.Outcomes = v.Outcomes[:1] }},
		{name: "unknown-outcome", change: func(v *report.ValidationReport) { v.Outcomes[0].TaskID = "unknown" }},
		{name: "duplicate-outcome", change: func(v *report.ValidationReport) { v.Outcomes[0] = v.Outcomes[1] }},
		{name: "empty-task-id", change: func(v *report.ValidationReport) { v.Tasks[0].ID = "" }},
		{name: "duplicate-task", change: func(v *report.ValidationReport) { v.Tasks[0] = v.Tasks[1] }},
		{name: "unplanned-outcome", change: func(v *report.ValidationReport) { v.Tasks = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validationRunFixture()
			tc.change(&r.Targets[0].Analysis.Validation)
			if _, err := report.SealRun(r); err == nil {
				t.Fatal("inconsistent validation task plan accepted as complete")
			}
		})
	}
}

func TestRunAcceptsOptionalDisabledTaskAndCompleteValidationOutcomes(t *testing.T) {
	for _, status := range []string{"completed", "not_applicable", "cached"} {
		t.Run(status, func(t *testing.T) {
			r := validationRunFixture()
			r.Targets[0].Analysis.Validation.Outcomes[0].Status = status
			slices.Reverse(r.Targets[0].Analysis.Validation.Outcomes)
			if _, err := report.SealRun(r); err != nil {
				t.Fatalf("optional disabled task or completion order rejected: %v", err)
			}
		})
	}
}

func TestDocumentValidationBindsEvaluationAndDetectsMutation(t *testing.T) {
	r, err := report.SealRun(runFixture())
	if err != nil {
		t.Fatal(err)
	}
	document := report.NewDocument(r, report.Evaluation{
		Decision:     report.Allow,
		RunDigest:    r.Digest,
		PolicyDigest: "policy",
	})
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded report.Document
	if err := json.Unmarshal(wire, &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("document does not survive JSON round trip: %s %v", wire, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*report.Document)
	}{
		{name: "schema", change: func(d *report.Document) { d.Schema = "future" }},
		{name: "binding", change: func(d *report.Document) { d.Evaluation.RunDigest = "another-run" }},
		{name: "decision", change: func(d *report.Document) { d.Evaluation.Decision = "unknown" }},
		{
			name:   "mutation",
			change: func(d *report.Document) { d.Run.Targets[0].Analysis.Findings[0].Message = "changed" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d report.Document
			if err := json.Unmarshal(wire, &d); err != nil {
				t.Fatal(err)
			}
			tc.change(&d)
			if err := d.Validate(); err == nil {
				t.Fatalf("invalid document accepted: %+v", d)
			}
		})
	}
}

func TestIncompleteDocumentCannotAllow(t *testing.T) {
	r := runFixture()
	r.State = report.RunIncomplete
	r.Targets[0].State = report.RunIncomplete
	r.Targets[0].Analysis.Coverage.Completeness = report.Partial
	r, err := report.SealRun(r)
	if err != nil {
		t.Fatal(err)
	}
	d := report.NewDocument(r, report.Evaluation{Decision: report.Allow, RunDigest: r.Digest})
	if err := d.Validate(); err == nil {
		t.Fatal("incomplete run allowed")
	}
	d.Evaluation.Decision = report.Review
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRunDigestNormalizesEmptyCollections(t *testing.T) {
	a := runFixture()
	a.Targets[0].Analysis.Dependencies.Declarations = nil
	b := runFixture()
	b.Targets[0].Analysis.Dependencies.Declarations = []report.Dependency{}
	a, err := report.SealRun(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err = report.SealRun(b)
	if err != nil || a.Digest != b.Digest {
		t.Fatalf("nil and empty collections differ: %v", err)
	}
}

func TestRunComparisonRequiresBothTargetsAndCompleteChanges(t *testing.T) {
	r := runFixture()
	r.Operation = report.CompareOperation
	r.Targets = append(r.Targets, runFixture().Targets[0])
	r.Targets[1].ID, r.Targets[1].Index = "target-1", 1
	r.Comparison = &report.UpdateDelta{Completeness: report.Complete}
	sealed, err := report.SealRun(r)
	if err != nil {
		t.Fatal(err)
	}
	d := report.NewDocument(sealed, report.Evaluation{Decision: report.Review, RunDigest: sealed.Digest})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Comparison.OmittedChanges = 1
	if _, err := report.SealRun(r); err == nil {
		t.Fatal("truncated comparison accepted as complete")
	}
	r.Comparison.OmittedChanges = 0
	r.Targets = r.Targets[:1]
	if _, err := report.SealRun(r); err == nil {
		t.Fatal("comparison with only one target accepted")
	}
}

func TestRunDigestRetainsExactLargeIntegerValues(t *testing.T) {
	a := runFixture()
	a.State, a.Targets[0].State = report.RunIncomplete, report.RunIncomplete
	a.Targets[0].Analysis.Coverage.Completeness = report.Partial
	a.Targets[0].Analysis.Extraction.Skipped = []report.SkippedObject{{
		Reason:       "object_byte_limit",
		DeclaredSize: 1 << 53,
	}}
	b := runFixture()
	b.State, b.Targets[0].State = report.RunIncomplete, report.RunIncomplete
	b.Targets[0].Analysis.Coverage.Completeness = report.Partial
	b.Targets[0].Analysis.Extraction.Skipped = []report.SkippedObject{{
		Reason:       "object_byte_limit",
		DeclaredSize: 1<<53 + 1,
	}}
	a, err := report.SealRun(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err = report.SealRun(b)
	if err != nil || a.Digest == b.Digest {
		t.Fatalf("different large integer values collapsed: %v", err)
	}
}

func BenchmarkSealRun(b *testing.B) {
	run := benchmarkRun(b, 5000)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := report.SealRun(run); err != nil {
			b.Fatal(err)
		}
	}
}

func semanticRunFixture() report.Run {
	r := runFixture()
	r.Targets[0].Analysis.Semantic = report.SemanticReport{
		Enabled: true, Completeness: report.Complete, CompletedRequests: 2,
		Tasks: []report.SemanticTask{{ID: "semantic-a"}, {ID: "semantic-b"}},
		Outcomes: []report.SemanticOutcome{{TaskID: "semantic-a", Status: "completed"}, {
			TaskID: "semantic-b",
			Status: "completed",
		}},
	}
	return r
}

func validationRunFixture() report.Run {
	r := runFixture()
	r.Targets[0].Analysis.Validation = report.ValidationReport{
		Completeness: report.Complete,
		Tasks:        []report.AnalysisTask{{ID: "analyzer-a", Required: true}, {ID: "optional-semantic"}},
		Outcomes: []report.TaskOutcome{{TaskID: "analyzer-a", Status: "completed"}, {
			TaskID: "optional-semantic",
			Status: "disabled",
		}},
	}
	return r
}

func runFixture() report.Run {
	return report.Run{
		Operation: report.ScanOperation, State: report.RunComplete,
		Engine: report.EngineIdentity{Version: "fixture-v1", RulepackDigest: "rules"},
		Plan: report.InspectionPlan{
			Name: "standard",
			Checks: []report.InspectionCheck{{
				ID:        "B",
				Selected:  true,
				Available: true,
			}, {
				ID:        "A",
				Selected:  true,
				Available: true,
			}},
		},
		Targets: []report.TargetResult{{
			ID:    "target-0",
			Index: 0,
			Label: "./plugin",
			State: report.RunComplete,
			Analysis: report.Analysis{
				Artifact: report.Artifact{SnapshotSHA256: "snapshot", InventoryComplete: true},
				Coverage: report.Coverage{
					Completeness: report.Complete,
					Checks:       []report.Check{{AnalyzerID: "A", Status: "completed"}},
					Files:        []report.FileCoverage{{Path: "SKILL.md", Completeness: report.Complete}},
				},
				Validation: report.ValidationReport{Completeness: report.Complete},
				Source:     &report.SourceProvenance{Kind: "local", TargetSHA256: "original"},
				Findings: []report.Finding{{
					ID:       "finding-b",
					RuleID:   "B",
					Severity: report.High,
					Evidence: report.Evidence{
						FileSHA256: "file",
						SpanSHA256: "span",
					},
					Trace: []report.TraceStep{{Role: "source"}, {Role: "sink"}},
				}, {
					ID:       "finding-a",
					RuleID:   "A",
					Severity: report.Low,
				}},
				Diagnostics: []report.Diagnostic{{Code: "info-b"}, {Code: "info-a"}},
			},
		}},
	}
}

func benchmarkRun(b *testing.B, count int) report.Run {
	b.Helper()
	run := runFixture()
	run.Targets[0].Analysis.Findings = make([]report.Finding, count)
	for i := range count {
		run.Targets[0].Analysis.Findings[i] = report.Finding{
			ID:       fmt.Sprintf("finding-%06d", count-i),
			RuleID:   "R",
			Severity: report.High,
			Location: report.Location{Path: "script.sh"},
		}
	}
	sealed, err := report.SealRun(run)
	if err != nil {
		b.Fatal(err)
	}
	return sealed
}
