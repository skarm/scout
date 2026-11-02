package analyzer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

// Deterministic synthetic bodies exercise token shapes without live credentials.
func providerTokenExamples() map[string]string {
	body := strings.Repeat("aB3dE5fG7", 12)
	return map[string]string{
		"SE002": "ghp_" + body[:36],
		"SE003": "glpat-" + body[:20],
		"SE004": "xoxb-123456789012-987654321098-" + body[:24],
		"SE005": "sk_live_" + body[:24],
		"SE006": "sk-proj-" + body[:72],
		"SE007": "sk-ant-api03-" + body[:93] + "AA",
	}
}

func providerTokenAnalyzer(t *testing.T, id string) analyzer.Analyzer {
	t.Helper()
	for _, a := range analyzer.NewCatalog(analyzer.Selection{}).Analyzers() {
		if a.Rule().ID == id {
			return a
		}
	}
	t.Fatalf("missing provider token rule %s", id)
	return nil
}

func TestProviderTokensInspectEveryCapturedByteStream(t *testing.T) {
	for id, token := range providerTokenExamples() {
		t.Run(id, func(t *testing.T) {
			a := providerTokenAnalyzer(t, id)
			for _, path := range []string{"SKILL.md", ".hidden/.env", "LICENSE", "tests/example.txt", "assets/payload.bin"} {
				text := "\x00\xffКлюч: \"" + token + "\"\n"
				doc := document.Prepare(t.Context(), artifact.NewFile(path, []byte(text), false))
				r, err := a.Find(t.Context(), doc, 10)
				if err != nil || !a.AppliesTo(doc) || r.Truncated || len(r.Matches) != 1 {
					t.Fatalf("%s: matches=%d truncated=%t error=%v", path, len(r.Matches), r.Truncated, err)
				}
				m := r.Matches[0]
				if m.Start != strings.Index(text, token) || m.End != m.Start+len(token) {
					t.Fatal("credential evidence does not identify the original token bytes")
				}
			}
		})
	}
}

func TestProviderTokenVariants(t *testing.T) {
	body := strings.Repeat("aB3dE5fG7", 29)
	for _, tc := range []struct{ name, id, token string }{
		{"github-fine-grained", "SE002", "github_pat_" + body[:82]},
		{"github-oauth", "SE002", "gho_" + body[:36]},
		{"github-user", "SE002", "ghu_" + body[:36]},
		{"github-legacy-installation", "SE002", "ghs_" + body[:36]},
		{"github-refresh", "SE002", "ghr_" + body[:76]},
		{"gitlab-extended", "SE003", "glpat-" + body[:200]},
		{"gitlab-placeholder-words-with-random-suffix", "SE003", "glpat-REPLACE_WITH_YOUR_GITLAB_TOKEN_" + body[:20]},
		{"slack-user", "SE004", "xoxp-123456789012-987654321098-123456789012-" + body[:32]},
		{"slack-bot-repeated-identifiers", "SE004", "xoxb-111111111111-111111111111-" + body[:24]},
		{"slack-user-repeated-identifiers", "SE004", "xoxp-111111111111-111111111111-111111111111-" + body[:32]},
		{"stripe-restricted", "SE005", "rk_live_" + body[:100]},
		{"stripe-test-secret", "SE005", "sk_test_" + body[:24]},
		{"stripe-test-restricted", "SE005", "rk_test_" + body[:24]},
		{"openai-service-account", "SE006", "sk-svcacct-" + body[:156]},
		{"openai-admin", "SE006", "sk-admin-" + body[:156]},
		{"openai-legacy", "SE006", "sk-" + body[:20] + "T3BlbkFJ" + body[:20]},
		{"anthropic-admin", "SE007", "sk-ant-admin01-" + body[:93] + "AA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := providerTokenAnalyzer(t, tc.id)
			doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(tc.token), false))
			r, err := a.Find(t.Context(), doc, 10)
			if err != nil || r.Truncated || len(r.Matches) != 1 || r.Matches[0].Start != 0 || r.Matches[0].End != len(tc.token) {
				t.Fatalf("matches=%d truncated=%t error=%v", len(r.Matches), r.Truncated, err)
			}
		})
	}
}

func TestProviderTokensRejectPlaceholdersAndPartialIdentifiers(t *testing.T) {
	body := strings.Repeat("aB3dE5fG7", 29)
	for _, tc := range []struct{ name, id, text string }{
		{"repeated-placeholder", "SE002", "ghp_" + strings.Repeat("x", 36)},
		{"low-entropy", "SE002", "ghp_" + strings.Repeat("ab", 18)},
		{"whole-payload-placeholder", "SE003", "glpat-REPLACE_WITH_YOUR_TOKEN"},
		{"gitlab-named-placeholder", "SE003", "glpat-REPLACE_WITH_YOUR_GITLAB_TOKEN"},
		{"gitlab-personal-placeholder", "SE003", "glpat-your-personal-access-token"},
		{"gitlab-personal-named-placeholder", "SE003", "glpat-REPLACE_WITH_YOUR_GITLAB_PERSONAL_ACCESS_TOKEN"},
		{"prefixed-identifier", "SE002", "my_ghp_" + body[:36]},
		{"prefixed-hyphen", "SE002", "my-ghp_" + body[:36]},
		{"overlong-github", "SE002", "ghp_" + body[:37]},
		{"overlong-gitlab", "SE003", "glpat-" + body[:256]},
		{"short-github", "SE002", "ghp_" + body[:35]},
		{"short-gitlab", "SE003", "glpat-" + body[:19]},
		{"slack-documentation", "SE004", "xoxb-your-bot-token"},
		{"slack-user-repeated-secret", "SE004", "xoxp-123456789012-987654321098-234567890123-" + strings.Repeat("x", 24)},
		{"slack-user-low-entropy-secret", "SE004", "xoxp-123456789012-987654321098-234567890123-" + strings.Repeat("abcd", 6)},
		{"slack-bot-repeated-secret", "SE004", "xoxb-123456789012-987654321098-" + strings.Repeat("x", 24)},
		{"slack-truncated", "SE004", "xoxb-123456789012-987654321098-" + body[:19]},
		{"stripe-public", "SE005", "pk_live_" + body[:40]},
		{"stripe-short", "SE005", "sk_live_" + body[:15]},
		{"openai-placeholder", "SE006", "sk-proj-" + strings.Repeat("X", 72)},
		{"anthropic-short", "SE007", "sk-ant-api03-" + body[:79]},
		{"provider-env-reference", "SE006", "OPENAI_API_KEY=${OPENAI_API_KEY}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := providerTokenAnalyzer(t, tc.id)
			doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(tc.text), false))
			r, err := a.Find(t.Context(), doc, 10)
			if err != nil || r.Truncated || len(r.Matches) != 0 {
				t.Fatalf("matches=%d truncated=%t error=%v", len(r.Matches), r.Truncated, err)
			}
		})
	}
}

func TestProviderTokenPlaceholdersDoNotHideAdjacentCredentials(t *testing.T) {
	for _, tc := range []struct{ name, id, placeholder string }{
		{"gitlab", "SE003", "glpat-REPLACE_WITH_YOUR_TOKEN"},
		{"gitlab-named", "SE003", "glpat-REPLACE_WITH_YOUR_GITLAB_TOKEN"},
		{"gitlab-personal", "SE003", "glpat-your-personal-access-token"},
		{"slack", "SE004", "xoxp-123456789012-987654321098-234567890123-" + strings.Repeat("x", 24)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := providerTokenAnalyzer(t, tc.id)
			token := providerTokenExamples()[tc.id]
			text := strings.Repeat(tc.placeholder+"\n", 64) + token
			doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(text), false))
			r, err := a.Find(t.Context(), doc, 1)
			if err != nil || r.Truncated || len(r.Matches) != 1 || r.Matches[0].Start != len(text)-len(token) {
				t.Fatalf("placeholder candidates hid a real-shaped token: matches=%d truncated=%t error=%v", len(r.Matches), r.Truncated, err)
			}
		})
	}
}

func TestProviderTokenDecodedEvidenceAndDeduplication(t *testing.T) {
	a := providerTokenAnalyzer(t, "SE002")
	token := providerTokenExamples()["SE002"]
	for _, tc := range []struct{ name, text, evidence string }{
		{"raw-json", `{"token":"` + token + `"}`, token},
		{"escaped-json", `{"token":"\u0067` + token[1:] + `"}`, `"\u0067` + token[1:] + `"`},
		{"invisible-control", "gh\u200bp_" + token[4:], "gh\u200bp_" + token[4:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "notes.txt"
			if strings.HasSuffix(tc.name, "json") {
				path = "config.json"
			}
			doc := document.Prepare(t.Context(), artifact.NewFile(path, []byte(tc.text), false))
			r, err := a.Find(t.Context(), doc, 10)
			if err != nil || r.Truncated || len(r.Matches) != 1 {
				t.Fatalf("matches=%d truncated=%t error=%v", len(r.Matches), r.Truncated, err)
			}
			m := r.Matches[0]
			if tc.text[m.Start:m.End] != tc.evidence {
				t.Fatal("decoded evidence lost its original carrier")
			}
		})
	}
}

func TestProviderTokenBudgetsAndCancellation(t *testing.T) {
	a := providerTokenAnalyzer(t, "SE002")
	token := providerTokenExamples()["SE002"]
	doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(token+"\n"+token), false))
	for _, budget := range []int{0, 1} {
		r, err := a.Find(t.Context(), doc, budget)
		if err != nil || !r.Truncated || len(r.Matches) != budget {
			t.Fatalf("budget=%d matches=%d truncated=%t error=%v", budget, len(r.Matches), r.Truncated, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.Find(ctx, doc, 10); err == nil {
		t.Fatal("token analysis ignored cancellation")
	}

	text := strings.Repeat("ghp_"+strings.Repeat("x", 36)+"\n", 65537)
	doc = document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(text), false))
	for _, budget := range []int{0, 1} {
		r, err := a.Find(t.Context(), doc, budget)
		if err != nil || !r.Truncated || len(r.Matches) != 0 {
			t.Fatal("exhausted candidate budget was reported as a complete negative")
		}
	}
}

func TestProviderTokenZeroBudgetProbesForOmittedMatches(t *testing.T) {
	for id, token := range providerTokenExamples() {
		t.Run(id, func(t *testing.T) {
			a := providerTokenAnalyzer(t, id)
			for _, tc := range []struct {
				name, text string
				omitted    bool
			}{
				{"clean", "Public documentation.", false},
				{"rejected-boundary", "my_" + token, false},
				{"raw-token", "Credential: " + token, true},
				{"hidden-token", "Credential: " + token[:2] + "\u200b" + token[2:], true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(tc.text), false))
					result, err := a.Find(t.Context(), doc, 0)
					if err != nil || len(result.Matches) != 0 || result.Truncated != tc.omitted {
						t.Fatalf("matches=%d truncated=%t want-omitted=%t error=%v", len(result.Matches), result.Truncated, tc.omitted, err)
					}
				})
			}
			doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte("Public documentation."), false))
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := a.Find(ctx, doc, 0); !errors.Is(err, context.Canceled) {
				t.Fatal("zero-budget probe lost cancellation")
			}
		})
	}
}

func TestProviderTokenEntropyBoundary(t *testing.T) {
	a := providerTokenAnalyzer(t, "SE003")
	for _, tc := range []struct {
		name, payload string
		matches       int
	}{
		{"below-three-bits", strings.Repeat("aB3dE5f", 4), 0},
		{"exactly-three-bits", strings.Repeat("aB3dE5fG", 3), 1},
		{"above-three-bits", strings.Repeat("aB3dE5fG7", 3), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "Credential: glpat-" + tc.payload
			doc := document.Prepare(t.Context(), artifact.NewFile("notes.txt", []byte(text), false))
			result, err := a.Find(t.Context(), doc, 1)
			if err != nil || result.Truncated || len(result.Matches) != tc.matches {
				t.Fatalf("matches=%d want=%d truncated=%t error=%v", len(result.Matches), tc.matches, result.Truncated, err)
			}
		})
	}
}
