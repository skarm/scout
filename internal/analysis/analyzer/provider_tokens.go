package analyzer

import (
	"context"
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/report"
)

// Token grammars are bounded observations, not provider validators. In
// particular, GitHub's newer stateless installation tokens and custom GitLab
// prefixes are outside this selected set. No credential is sent to a provider.
type providerTokenCheck struct {
	rule       report.Rule
	expression *regexp.Regexp
	hint       *patternLiteralFilter
}

//nolint:gochecknoglobals // Immutable compiled checks are shared across scans.
var compiledProviderTokens = sync.OnceValue(func() []Analyzer {
	return []Analyzer{
		newProviderToken(ruleSE002, "GitHub", `(?:gh[pous]_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{76}|github_pat_[A-Za-z0-9_]{82})`, "Selected PAT, OAuth, user, refresh and legacy installation formats; stateless installation tokens are not recognized."),
		newProviderToken(ruleSE003, "GitLab", `glpat-[A-Za-z0-9_-]{20,255}`, "Default glpat- prefix only; custom instance prefixes and other GitLab token classes are not recognized."),
		newProviderToken(ruleSE004, "Slack", `xox[bp]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[A-Za-z0-9]{20,64}`, "Selected bot and user token formats only; app-level, session and rotated token formats are not recognized."),
		newProviderToken(ruleSE005, "Stripe", `(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}`, "Selected live and test secret/restricted keys; publishable pk_ keys are not credentials for this check."),
		newProviderToken(ruleSE006, "OpenAI", `sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{48,255}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`, "Selected project, service-account, admin and legacy key shapes; prefixes and lengths are heuristic and may change."),
		newProviderToken(ruleSE007, "Anthropic", `sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,128}`, "Selected api03/admin01 key shapes; prefixes and lengths are heuristic and may change."),
	}
})

//nolint:gochecknoglobals // Read-only token prefixes and a whole-payload placeholder grammar.
var (
	providerTokenPrefixes = strings.Fields("github_pat_ ghp_ gho_ ghu_ ghs_ ghr_ glpat- xoxb- xoxp- sk_live_ rk_live_ sk_test_ rk_test_ sk-proj- sk-svcacct- sk-admin- sk-ant-api03- sk-ant-admin01- sk-")
	providerPlaceholder   = regexp.MustCompile(`(?i)^(?:your|example|dummy|sample|test|fake|placeholder|replace|insert|redacted)(?:[_-](?:api|access|auth|key|token|secret|here|with|your|value|actual|example|placeholder|gitlab|personal|[x0]+))*$`)
)

func providerTokenRules() []Analyzer {
	return append([]Analyzer(nil), compiledProviderTokens()...)
}

func newProviderToken(id, provider, expression, limitation string) providerTokenCheck {
	return providerTokenCheck{
		rule: report.Rule{
			ID: id, Version: "3", Title: provider + " token-shaped credential literal",
			Description: "A bounded " + provider + " token shape is present in captured content.",
			Severity:    report.High, Category: "credential-material", Method: "bounded-provider-token-shape",
			Limitation: limitation + " Token boundaries, whole-secret-payload placeholders and a minimum secret-payload Shannon entropy of 3 bits/byte are checked; Slack numeric segments are excluded. Low-entropy credentials can be missed. No liveness, ownership or authorization is established. Raw bytes, supported security views and decoded structured scalars are inspected; other encodings and constructed tokens remain outside scope. Values and source excerpts are never included in findings.",
		},
		expression: regexp.MustCompile(expression),
		hint:       literalFilter(expression),
	}
}

func (a providerTokenCheck) Rule() report.Rule { return a.rule }

func (providerTokenCheck) AppliesTo(document.File) bool { return true }

func (a providerTokenCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	matcher := familyAnalyzer{
		patterns: []*regexp.Regexp{a.expression},
		exempt:   providerTokenExempt, candidateLimit: 65536,
	}
	if a.hint != nil {
		matcher.patternHints = []patternLiteralFilter{*a.hint}
	}

	return matcher.findDocument(ctx, d, budget, patternStages{})
}

func providerTokenExempt(text string, start, end int) bool {
	if start > 0 && providerTokenByte(text[start-1]) || end < len(text) && providerTokenByte(text[end]) {
		return true
	}

	payload := providerTokenPayload(text[start:end])
	if providerPlaceholder.MatchString(payload) {
		return true
	}

	var counts [256]int
	for i := range len(payload) {
		counts[payload[i]]++
	}

	entropy := 0.0

	for _, count := range counts {
		if count > 0 {
			probability := float64(count) / float64(len(payload))
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy < 3
}

// Slack numeric segments must neither supply entropy to an inert secret nor
// dilute the entropy of a credential-shaped final segment. Evidence still
// identifies the complete original token.
func providerTokenPayload(token string) string {
	if strings.HasPrefix(token, "xoxb-") || strings.HasPrefix(token, "xoxp-") {
		return token[strings.LastIndexByte(token, '-')+1:]
	}

	for _, prefix := range providerTokenPrefixes {
		if strings.HasPrefix(token, prefix) {
			return token[len(prefix):]
		}
	}

	return token
}

func providerTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}
