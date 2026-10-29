package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestCompiledKnowledgeCanBeInspectedWithoutScanning(t *testing.T) {
	for _, mode := range []string{"", "discovery", "intent", "quality", "assessment", "proposal_assessment"} {
		t.Run(mode, func(t *testing.T) {
			var out, errs bytes.Buffer
			args := []string{"knowledge"}
			if mode != "" {
				args = append(args, "--mode", mode)
			}
			if c := cli.Run(context.Background(), args, &out, &errs); c != 0 || errs.Len() != 0 {
				t.Fatalf("%d %s", c, errs.String())
			}
			if mode == "" {
				var r knowledge.Pack
				if json.Unmarshal(out.Bytes(), &r) != nil || r.Manifest.SHA256 != knowledge.Inventory().SHA256 || len(r.Guidance) < 100 || len(r.Topics) != 52 || len(r.Sources) != 14 {
					t.Fatal("incomplete catalog")
				}
				want, _ := json.Marshal(knowledge.Export())
				got, _ := json.Marshal(r)
				if !bytes.Equal(got, want) {
					t.Fatal("CLI knowledge differs from the trusted runtime export")
				}
			} else {
				p, _ := knowledge.Prompt(mode)
				if out.String() != p {
					t.Fatal("not exact runtime prompt")
				}
			}
		})
	}
	for _, args := range [][]string{{"knowledge", "target"}, {"knowledge", "--mode", "../../SKILL.md"}, {"knowledge", "--mode", "unknown"}} {
		var out, errs bytes.Buffer
		if cli.Run(context.Background(), args, &out, &errs) != 2 || out.Len() != 0 {
			t.Fatal("unsafe external instruction load")
		}
	}
	var errs bytes.Buffer
	if cli.Run(context.Background(), []string{"knowledge"}, failWriter{}, &errs) != 2 {
		t.Fatal("output failure ignored")
	}
}

func TestRuleDescriptorsExposeGuidance(t *testing.T) {
	var out, errs bytes.Buffer
	if cli.Run(context.Background(), []string{"rules", "--all"}, &out, &errs) != 0 {
		t.Fatal(errs.String())
	}
	for _, s := range []string{`"NV-TR1M"`, `"NV-SC7M"`, `"remediation"`, `"review_checks"`, `"sources"`} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("missing", s)
		}
	}
}

// A scripted loopback reviewer exercises CLI flag selection as well as Scan.
// Its answers are test inputs, not measured SQL classification performance.
func TestKnowledgeSQLReachesActualCLIReport(t *testing.T) {
	for _, risk := range []bool{false, true} {
		name := "bound-parameter"
		if risk {
			name = "dynamic-query"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := `db.query("SELECT name FROM accounts WHERE id = $1", [input]);`
			if risk {
				source = `db.query("SELECT name FROM accounts WHERE id = " + input);`
			}
			if err := os.WriteFile(filepath.Join(root, "query.ts"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Messages []struct{ Role, Content string } `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Messages) != 2 {
					t.Error("bad CLI request", err)
					return
				}
				var req review.Request
				if err := json.Unmarshal([]byte(body.Messages[1].Content), &req); err != nil {
					t.Error(err)
					return
				}
				response := review.Response{
					SchemaVersion: review.ProtocolVersion,
					RequestID:     req.RequestID,
					Proposals:     []review.Proposal{},
					Assessments:   []review.Assessment{},
				}
				if risk && req.Mode == "discovery" {
					ex := req.Excerpts[0]
					response.Proposals = []review.Proposal{{
						Reason:   "knowledge:K-SQL-PARAMS",
						Severity: "high",
						Evidence: []review.Citation{{
							ExcerptID: ex.ID,
							SHA256:    ex.SHA256,
						}},
					}}
				}
				for _, f := range req.Findings {
					response.Assessments = append(response.Assessments, review.Assessment{
						FindingID: f.ID,
						Verdict:   "confirmed",
						Reason:    "supported_by_context",
						Evidence:  f.Evidence,
					})
				}
				raw, _ := json.Marshal(response)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{
					"index":         0,
					"finish_reason": "stop",
					"message": map[string]any{
						"role":    "assistant",
						"content": string(raw),
					},
				}}})
			}))
			defer srv.Close()
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "--profile", "basic", "--format", "json", "--semantic", "--allow-source-upload", "--llm-allow-loopback", "--llm-endpoint", srv.URL + "/v1/chat/completions", "--llm-model", "scripted-fixture-no-live-model", root}, &out, &errs)
			var result scantest.Result
			if err := scantest.DecodeJSON(out.Bytes(), &result); err != nil || errs.Len() != 0 && code != 2 {
				t.Fatalf("CLI failed code=%d: %s %v", code, errs.String(), err)
			}
			if result.Semantic.Completeness != report.Complete {
				t.Fatalf("SQL result rejected by actual CLI path: %+v", result.Semantic.Outcomes)
			}
			if risk {
				if len(result.Semantic.Proposals) != 1 || result.Semantic.Proposals[0].KnowledgeTopicID != "K-SQL-PARAMS" || len(result.Semantic.ProposalAssessments) != 1 || result.Evaluation.Decision == report.Allow || code == 0 {
					t.Fatal("SQL hypothesis lost before CLI report or auto-allowed")
				}
			} else if len(result.Semantic.Proposals) != 0 {
				t.Fatal("empty fixture response invented a SQL hypothesis")
			}
		})
	}
}
