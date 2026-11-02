package scout_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/report"
)

func TestProviderTokenScanPreservesEvidenceWithoutDisclosingValues(t *testing.T) {
	root := t.TempDir()
	body := strings.Repeat("aB3dE5fG7", 12)
	tokens := map[string]string{
		"SE002": "ghp_" + body[:36],
		"SE003": "glpat-" + body[:20],
		"SE004": "xoxb-123456789012-987654321098-" + body[:24],
		"SE005": "sk_live_" + body[:24],
		"SE006": "sk-proj-" + body[:72],
		"SE007": "sk-ant-api03-" + body[:93] + "AA",
	}
	for id, token := range tokens {
		scenario.WriteFile(t, root, ".hidden/"+id+".txt", "Ключ: \""+token+"\"\n")
	}
	scanner := scenario.Scanner(t, scantest.DefaultConfig())
	result, err := scanner.Scan(t.Context(), root)
	if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
		t.Fatal(err)
	}
	if result.Evaluation.Decision != report.Block {
		t.Fatal("provider credentials did not block under the high-severity test policy")
	}
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		token, ok := tokens[finding.RuleID]
		if !ok {
			continue
		}
		digest := sha256.Sum256([]byte(token))
		if finding.Evidence.SpanSHA256 != hex.EncodeToString(digest[:]) || finding.Location.ByteEnd-finding.Location.ByteStart != len(token) {
			t.Fatalf("incorrect provider credential evidence for %s", finding.RuleID)
		}
		seen[finding.RuleID] = true
	}
	if len(seen) != len(tokens) {
		t.Fatalf("detected %d of %d provider rules", len(seen), len(tokens))
	}
	prepared, err := report.Prepare(result.Document)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := prepared.Write(&out, format); err != nil {
			t.Fatal(err)
		}
		for id, token := range tokens {
			if strings.Contains(out.String(), token) || strings.Contains(out.String(), token[len(token)-16:]) {
				t.Fatalf("%s report disclosed credential material for %s", format, id)
			}
		}
	}
}

func TestProviderPlaceholdersDoNotBlockOrHideAdjacentCredentials(t *testing.T) {
	body := strings.Repeat("aB3dE5fG7", 12)
	scanner := scenario.Scanner(t, scantest.DefaultConfig())

	for _, tc := range []struct{ name, id, placeholder, token string }{
		{"gitlab-named", "SE003", "glpat-REPLACE_WITH_YOUR_GITLAB_TOKEN", "glpat-" + body[:20]},
		{"gitlab-personal", "SE003", "glpat-your-personal-access-token", "glpat-" + body[:20]},
		{"slack-user", "SE004", "xoxp-123456789012-987654321098-234567890123-" + strings.Repeat("x", 24), "xoxp-123456789012-987654321098-234567890123-" + body[:32]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, adjacent := range []bool{false, true} {
				text := "Documentation example: " + tc.placeholder + "\n"
				wantDecision, wantFindings := report.Allow, 0
				if adjacent {
					text += "Credential: " + tc.token + "\n"
					wantDecision, wantFindings = report.Block, 1
				}
				result, err := scanner.ScanBytes(t.Context(), "notes.txt", []byte(text))
				if err != nil || result.Coverage.Completeness != report.Complete || result.Evaluation.Decision != wantDecision || len(result.Findings) != wantFindings {
					t.Fatalf("adjacent=%t decision=%s completeness=%s findings=%d error=%v", adjacent, result.Evaluation.Decision, result.Coverage.Completeness, len(result.Findings), err)
				}
				if adjacent {
					finding := result.Findings[0]
					if finding.RuleID != tc.id || finding.Location.ByteStart != strings.Index(text, tc.token) || finding.Location.ByteEnd-finding.Location.ByteStart != len(tc.token) {
						t.Fatal("placeholder filter changed the adjacent credential evidence")
					}
				}
			}
		})
	}
}

func TestProviderTokenExactRuleQuotaRemainsComplete(t *testing.T) {
	token := "ghp_" + strings.Repeat("aB3dE5fG7", 4)
	for _, extra := range []bool{false, true} {
		root := t.TempDir()
		scenario.WriteFile(t, root, "a.txt", "Credential: "+token+"\n")
		last := "Public documentation.\n"
		wantCompleteness, wantCode := report.Complete, 1
		if extra {
			last = "Credential: " + token + "\n"
			wantCompleteness, wantCode = report.Partial, 2
		}
		scenario.WriteFile(t, root, "z.txt", last)
		config := scantest.DefaultConfig()
		config.Scanner.Limits.Analysis.MaxMatchesPerRule = 1
		scanner := scenario.Scanner(t, config)
		result, err := scanner.Scan(t.Context(), root)
		if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
			t.Fatal(err)
		}
		if errors.Is(err, scantest.ErrIncomplete) != extra || result.Coverage.Completeness != wantCompleteness || scantest.ExitCode(result) != wantCode || result.Evaluation.Decision != report.Block {
			t.Fatalf("extra=%t completeness=%s exit=%d decision=%s error=%v", extra, result.Coverage.Completeness, scantest.ExitCode(result), result.Evaluation.Decision, err)
		}
		if len(result.Findings) != 1 || result.Findings[0].RuleID != "SE002" || result.Findings[0].Location.Path != "a.txt" {
			t.Fatal("exact-quota probe lost the retained credential evidence")
		}
	}
}
