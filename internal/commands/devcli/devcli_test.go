package devcli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/commands/devcli"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/internal/dev/provenance"
	"github.com/skarm/scout/internal/dev/replay"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestDeveloperCommandsKeepSavedEvidenceAndAccounting(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("default developer scans require the linked native profile")
	}
	root := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		var out, diag bytes.Buffer
		if code := devcli.Run(t.Context(), args, &out, &diag); code != 0 {
			t.Fatalf("%v => %d: %s", args, code, &diag)
		}
		return out.Bytes()
	}
	corpus, err := json.Marshal(evaluation.Corpus{
		SchemaVersion: 1,
		Kind:          "authored_regression_not_holdout",
		Cases: []evaluation.Case{{
			ID:       "benign",
			Category: "ordinary",
			Label:    "benign",
			Path:     "sample.txt",
			Content:  "ordinary documentation",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(root, "corpus.json")
	if err := os.WriteFile(corpusPath, corpus, 0o600); err != nil {
		t.Fatal(err)
	}
	var measured evaluation.Report
	if err := json.Unmarshal(run("evaluate", corpusPath), &measured); err != nil {
		t.Fatal(err)
	}
	if measured.EngineVersion != scout.Version() || len(measured.Results) != 1 || measured.Results[0].ID != "benign" || measured.Overall.CompleteNegativeBenign+measured.Overall.UnresolvedBenign != 1 {
		t.Fatal(measured)
	}
	input := []byte(`{"id":"` + strings.Repeat("a", 64) + `","files":[{"name":"sample.txt","data":"b3JkaW5hcnk="}]}` + "\n")
	inputPath, resultPath := filepath.Join(root, "input.jsonl"), filepath.Join(root, "result.jsonl")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var summary replay.Summary
	if err := json.Unmarshal(run("replay", "--input", inputPath, "--output", resultPath, "--workers", "1"), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Inputs != 1 || summary.RuntimeErrors != 0 {
		t.Fatal(summary)
	}
	var comparison provenance.Comparison
	args := make([]string, 0, 10)
	args = append(args, "provenance", "compare", "--root", root, "--before", "result.jsonl", "--replay", "result.jsonl")
	if err := json.Unmarshal(run(args...), &comparison); err != nil {
		t.Fatal(err)
	}
	if comparison.ChangedRows != 0 || comparison.AfterInputs != 1 || comparison.BeforeInputs != 1 {
		t.Fatal(comparison)
	}
	run(append(args, "--output", "comparison.json")...)
	if _, err := provenance.Read(root, "comparison.json"); err == nil {
		t.Fatal("comparison unexpectedly has a manifest schema")
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(input); err != nil {
		t.Error(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	gzipPath := filepath.Join(root, "input.jsonl.gz")
	if err := os.WriteFile(gzipPath, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(run("replay", "--input", gzipPath, "--output", filepath.Join(root, "compressed-result.jsonl"), "--workers", "1"), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Inputs != 1 || summary.RuntimeErrors != 0 {
		t.Fatal(summary)
	}
}

func TestDeveloperCommandsRejectInvalidBoundaries(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"unknown-command"},
		{"evaluate"},
		{"evaluate", "--timeout=0", "corpus"},
		{"evaluate", "--unknown"},
		{"evaluate", "missing"},
		{"replay"},
		{"replay", "--unknown"},
		{"replay", "--input=missing", "--output=out"},
		{"releasecheck"},
		{"releasecheck", "--unknown"},
		{"releasecheck", "--binary=missing"},
		{"provenance"},
		{"provenance", "unknown"},
		{"provenance", "compare", "extra"},
		{"provenance", "compare", "--unknown"},
		{"provenance", "generate", "--root=missing"},
		{"provenance", "verify", "--manifest=missing"},
	} {
		var out, diag bytes.Buffer
		if code := devcli.Run(t.Context(), args, &out, &diag); code != 2 || diag.Len() == 0 && out.Len() == 0 {
			t.Fatalf("%v => %d, %s", args, code, &diag)
		}
	}
}

func TestDeveloperReleaseUsesSelectedTrustedBinary(t *testing.T) {
	bin := os.Getenv("SCOUT_TEST_BIN")
	if bin == "" {
		t.Skip("set SCOUT_TEST_BIN to the selected release")
	}
	for _, extra := range [][]string{nil, {"--inspect-only"}} {
		var out, diag bytes.Buffer
		args := append([]string{"releasecheck", "--binary", bin}, extra...)
		code := devcli.Run(t.Context(), args, &out, &diag)
		want := 0
		if len(extra) != 0 {
			want = 2
		}
		if code != want || !json.Valid(out.Bytes()) {
			t.Fatal(code, &out, &diag)
		}
	}
}
