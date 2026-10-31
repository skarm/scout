package devcli_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/scout/internal/commands/devcli"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/review"
)

func TestEvaluateCLIReportsPackageSplit(t *testing.T) {
	var out, diag bytes.Buffer
	code := devcli.Run(t.Context(), []string{"evaluate", "--profile", "custom", "--split", "holdout", "../../../testdata/security-corpus/packages.json"}, &out, &diag)
	var r evaluation.Report
	if runtime.GOOS == "windows" {
		if code != 2 || json.Unmarshal(out.Bytes(), &r) != nil || r.Completed || r.SelectedCases != 3 || len(r.Results) != 1 {
			t.Fatalf("unsupported executable metadata must preserve partial results: code=%d report=%+v diag=%s", code, r, &diag)
		}
		return
	}
	if code != 0 || json.Unmarshal(out.Bytes(), &r) != nil || !r.Completed || r.SelectedCases != 3 || len(r.Results) != 3 || r.Overall.DetectedPositive != 1 || r.Overall.MissedPositive != 1 || r.Overall.CompleteNegativeBenign != 1 || len(r.Splits) != 1 {
		t.Fatalf("code=%d report=%+v diag=%s", code, r, &diag)
	}
}

func TestEvaluateCLIReviewRequiresGrantAndKeepsUsage(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var wire struct{ Messages []struct{ Content string } }
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || len(wire.Messages) != 2 {
			t.Error("invalid provider envelope", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request review.Request
		if err := json.Unmarshal([]byte(wire.Messages[1].Content), &request); err != nil {
			t.Error(err)
		}
		response, err := json.Marshal(review.Response{SchemaVersion: review.ProtocolVersion, RequestID: request.RequestID, Proposals: []review.Proposal{}, Assessments: []review.Assessment{}})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]any{
			"model": "fixture", "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 10},
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": string(response)}}},
		})
		if err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	config := filepath.Join(root, "review.json")
	data, err := json.Marshal(map[string]any{
		"schema": "scout.config/v1", "profile": "custom", "checks": map[string]bool{"patterns": false, "python": false, "yaml": false, "toml": false, "yara": false},
		"review": map[string]any{"provider": "chat-completions", "endpoint": server.URL + "/v1/chat/completions", "model": "fixture", "allow_loopback": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join(root, "corpus.json")
	if err := os.WriteFile(corpus, []byte(`{"schema_version":1,"kind":"authored_regression_not_holdout","cases":[{"id":"doc","category":"docs","label":"benign","path":"README.txt","content":"SYNTHETIC_PRIVATE_SOURCE ordinary documentation"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []bool{false, true} {
		var out, diag bytes.Buffer
		args := []string{"evaluate", "--llm-config", config, "--input-usd-per-million", "2", "--output-usd-per-million", "4"}
		if grant {
			args = append(args, "--allow-source-upload")
		}
		code := devcli.Run(t.Context(), append(args, corpus), &out, &diag)
		if !grant {
			if code != 2 || calls.Load() != 0 || out.Len() != 0 {
				t.Fatal("ungranted source upload", code, &diag)
			}
			continue
		}
		var report evaluation.Report
		if code != 0 || json.Unmarshal(out.Bytes(), &report) != nil || report.LLM == nil || !report.LLM.Usage.Complete || report.LLM.EstimatedCostUSD == nil || report.Overall.CompleteNegativeBenign != 1 || report.LLM.Overall.CompleteNegativeBenign != 1 || calls.Load() == 0 {
			t.Fatalf("code=%d report=%+v diag=%s", code, report, &diag)
		}
		if strings.Contains(out.String(), "SYNTHETIC_PRIVATE_SOURCE") || strings.Contains(out.String(), server.URL) {
			t.Fatal("private source or raw endpoint entered evaluation report")
		}
	}
}
