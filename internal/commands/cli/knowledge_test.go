package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
	"github.com/skarm/scout/rulepack"
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

func TestRulepackCreateInspectAndSourceProtection(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rules.yar")
	artifact := filepath.Join(dir, "rules.json")
	rules := []byte(`rule fixture { strings: $marker="RULEPACK_SENTINEL_001" condition: $marker }`)
	if err := os.WriteFile(source, rules, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	args := []string{"rules", "pack", "create", "--id", "team/agent", "--version", "1.2.3", "--yara", source, "--output", artifact}
	if code := cli.Run(t.Context(), args, &out, &diagnostics); code != 0 || out.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("create: code=%d diagnostics=%s", code, &diagnostics)
	}
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	pin := hex.EncodeToString(digest[:])
	if _, err := rulepack.Parse(data, pin); err != nil {
		t.Fatal(err)
	}
	args = []string{"rules", "pack", "inspect", "--sha256", pin, artifact}
	if code := cli.Run(t.Context(), args, &out, &diagnostics); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("inspect: code=%d diagnostics=%s", code, &diagnostics)
	}
	var identity report.RulepackIdentity
	if err := json.Unmarshal(out.Bytes(), &identity); err != nil || identity.ID != "team/agent" || identity.Version != "1.2.3" || identity.SHA256 != pin || bytes.Contains(out.Bytes(), []byte("RULEPACK_SENTINEL_001")) {
		t.Fatal("inspect did not return source-free verified identity", err)
	}
	for _, args := range [][]string{
		{"rules", "pack"},
		{"rules", "pack", "unknown"},
		{"rules", "pack", "create"},
		{"rules", "pack", "inspect"},
		{"rules", "pack", "inspect", "--sha256", strings.Repeat("0", 64), artifact},
		{"rules", "pack", "create", "--id", "team/agent", "--version", "1", "--yara", source, "--output", source},
	} {
		out.Reset()
		diagnostics.Reset()
		if code := cli.Run(t.Context(), args, &out, &diagnostics); code != 2 || out.Len() != 0 {
			t.Fatalf("invalid package operation accepted: %v code=%d", args, code)
		}
	}
	got, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(got, rules) {
		t.Fatal("package creation overwrote its source", err)
	}
	out.Reset()
	diagnostics.Reset()
	if code := cli.Run(t.Context(), []string{"rules", "pack", "create", "--id", "team/agent", "--version", "1.2.3", "--yara", source}, &out, &diagnostics); code != 0 || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("stdout and file artifacts differ", code)
	}
}

func TestRulepackCLISelectionBoundariesAndPins(t *testing.T) {
	trusted, root := t.TempDir(), t.TempDir()
	path, input := filepath.Join(trusted, "rules.json"), filepath.Join(root, "input.txt")
	data, err := rulepack.Create("team/agent", "1.2.3", []byte(`rule fixture { meta: category="malware" strings: $marker="RULEPACK_SENTINEL_001" condition: $marker }`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("RULEPACK_SENTINEL_001"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(data)
	flags := []string{"scan", "--profile", "custom", "--checks", "yara", "--scope", "selected", "--format", "json", "--rulepack", path, "--rulepack-sha256", hex.EncodeToString(pin[:]), input}
	var out, diagnostics bytes.Buffer
	code := cli.Run(t.Context(), flags, &out, &diagnostics)
	if signatures.Backend().Available {
		if code != 1 || !bytes.Contains(out.Bytes(), []byte(`"version": "1.2.3"`)) || diagnostics.Len() != 0 {
			t.Fatalf("selected package failed: code=%d diagnostics=%s", code, &diagnostics)
		}
	} else if code != 2 {
		t.Fatal("selected package bypassed missing backend")
	}
	empty := filepath.Join(trusted, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "rules.json")
	if err := os.WriteFile(inside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", "--profile", "custom", "--checks", "none", "--rulepack", empty, input},
		{"scan", "--profile", "custom", "--checks", "none", "--rulepack", path, input},
		{"scan", "--profile", "custom", "--checks", "yara", "--rulepack", path, "--rulepack-sha256", strings.Repeat("0", 64), input},
		{"scan", "--profile", "custom", "--checks", "yara", "--rulepack", inside, root},
		{"scan", "--profile", "custom", "--checks", "yara", "--rulepack", path, "--yara-rules", input, input},
		{"scan", "--profile", "custom", "--checks", "yara", "--rulepack", path, "--output", path, input},
	} {
		out.Reset()
		diagnostics.Reset()
		if code := cli.Run(t.Context(), args, &out, &diagnostics); code != 2 {
			t.Fatalf("unsafe package selection accepted: %v code=%d", args, code)
		}
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, data) {
		t.Fatal("report overwrote its selected rulepack", err)
	}
}

func TestRulepackCommandsHonorCancelledContext(t *testing.T) {
	dir := t.TempDir()
	source, artifact := filepath.Join(dir, "rules.yar"), filepath.Join(dir, "rules.json")
	rules := []byte("rule fixture { condition:true }")
	if err := os.WriteFile(source, rules, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := rulepack.Create("team/agent", "1.2.3", rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"rules", "pack", "create", "--id", "team/agent", "--version", "1.2.3", "--yara", source},
		{"rules", "pack", "inspect", artifact},
	} {
		t.Run(args[2], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var out, diagnostics bytes.Buffer
			if code := cli.Run(ctx, args, &out, &diagnostics); code != 2 || out.Len() != 0 {
				t.Fatalf("cancelled command published a successful artifact/identity: %v code=%d bytes=%d", args, code, out.Len())
			}
		})
		t.Run(args[2]+"/during-output", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			out := &rulepackCancelWriter{cancel: cancel}
			var diagnostics bytes.Buffer
			if code := cli.Run(ctx, args, out, &diagnostics); code != 2 || out.buffer.Len() == 0 {
				t.Fatalf("cancellation while publishing reported success: code=%d bytes=%d", code, out.buffer.Len())
			}
		})
	}
}

type rulepackCancelWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (w *rulepackCancelWriter) Write(data []byte) (int, error) {
	w.cancel()
	return w.buffer.Write(data)
}
