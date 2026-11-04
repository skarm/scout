package devcli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/devcli"
	"github.com/skarm/scout/internal/dev/evaluation"
)

func TestCLIManualLabelReviewWorkflow(t *testing.T) {
	corpusPath, reviewPath := cliLabelReviewFixture(t)
	var out, diag bytes.Buffer
	base := make([]string, 0, 9)
	base = append(base, "evaluate", "--profile", "custom", "--split", "holdout", "--require-independent", "--max-fpr", "0")
	if code := devcli.Run(t.Context(), append(base, corpusPath), &out, &diag); code != 1 {
		t.Fatalf("unreviewed input unexpectedly passed: code=%d diagnostics=%s", code, &diag)
	}
	out.Reset()
	if code := devcli.Run(t.Context(), []string{"corpus", "review-template", "--corpus", corpusPath, "--output", corpusPath}, &out, &diag); code != 2 {
		t.Fatal("review template replaced its source corpus")
	}
	args := make([]string, 0, len(base)+5)
	args = append(args, base...)
	args = append(args, "--label-review", reviewPath, "--trusted-label-reviewer", "fixture-reviewer", corpusPath)
	if code := devcli.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
		t.Fatalf("pending template approved labels: code=%d diagnostics=%s", code, &diag)
	}
	completeCLIReview(t, reviewPath)
	if code := devcli.Run(t.Context(), args, &out, &diag); code != 0 {
		t.Fatalf("completed fixture review failed: code=%d diagnostics=%s", code, &diag)
	}
	var report evaluation.Report
	if json.Unmarshal(out.Bytes(), &report) != nil || report.Gate == nil || !report.Gate.Passed || report.LabelReview == nil || report.LabelReview.ReviewedCases != 1 || report.Results[0].Label != "benign" {
		t.Fatalf("review provenance missing from successful measurement: %s", &out)
	}
	if strings.Contains(out.String(), "PRIVATE_REVIEW_RATIONALE") || strings.Contains(out.String(), "review.example.invalid") {
		t.Fatal("review rationale or evidence URL leaked into output")
	}
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpusPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := devcli.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
		t.Fatal("review accepted after corpus bytes changed")
	}
}

func TestIndependentCorpusNameAloneCannotPass(t *testing.T) {
	corpusPath, _ := cliLabelReviewFixture(t)
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("external_unreviewed_corpus"), []byte("independent_labelled_corpus"))
	data = bytes.ReplaceAll(data, []byte(`"ambiguous"`), []byte(`"benign"`))
	if err := os.WriteFile(corpusPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := devcli.Run(t.Context(), []string{"evaluate", "--profile", "custom", "--split", "holdout", "--require-independent", corpusPath}, &out, &diag)
	var report evaluation.Report
	if code != 1 || json.Unmarshal(out.Bytes(), &report) != nil || report.Gate == nil || !slices.Contains(report.Gate.Reasons, "trusted_independent_label_review_required") {
		t.Fatalf("a corpus name became independent authority: code=%d output=%s diagnostics=%s", code, &out, &diag)
	}
}

func TestLabelReviewPreflightPrecedesReviewerConfiguration(t *testing.T) {
	corpusPath, reviewPath := cliLabelReviewFixture(t)
	completeCLIReview(t, reviewPath)
	var out, diag bytes.Buffer
	args := []string{"evaluate", "--label-review", reviewPath, "--trusted-label-reviewer", "untrusted", "--llm-config", filepath.Join(t.TempDir(), "must-not-be-read"), "--allow-source-upload", corpusPath}
	if code := devcli.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "not explicitly trusted") {
		t.Fatalf("invalid labels did not fail before provider setup: code=%d diagnostics=%s", code, &diag)
	}
}

func cliLabelReviewFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	corpusPath, reviewPath := filepath.Join(root, "corpus.json"), filepath.Join(root, "review.json")
	corpus := evaluation.Corpus{SchemaVersion: 2, Kind: "external_unreviewed_corpus", Sources: []evaluation.Source{{ID: "fixture", Origin: "https://example.invalid/fixture", Revision: "synthetic-fixture", License: "MIT", LabelReview: "Pending; synthetic regression only."}}, Cases: []evaluation.Case{{ID: "doc", Category: "docs", Label: "ambiguous", SourceID: "fixture", Split: "holdout", Files: []evaluation.File{{Path: "README.txt", Content: "Ordinary fixture text."}}}}}
	data, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpusPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if code := devcli.Run(t.Context(), []string{"corpus", "review-template", "--corpus", corpusPath, "--output", reviewPath}, &out, &diag); code != 0 || out.Len() != 0 {
		t.Fatalf("cannot prepare review template: code=%d diagnostics=%s", code, &diag)
	}
	return corpusPath, reviewPath
}

func completeCLIReview(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document evaluation.LabelReviewDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document.Independent = true
	for i := range document.Reviews {
		document.Reviews[i].Label = "benign"
		document.Reviews[i].ReviewerID = "fixture-reviewer"
		document.Reviews[i].ReviewedAt = "2026-01-01T00:00:00Z"
		document.Reviews[i].Rationale = "PRIVATE_REVIEW_RATIONALE synthetic test only."
		document.Reviews[i].Evidence = []string{"https://review.example.invalid/fixture"}
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
