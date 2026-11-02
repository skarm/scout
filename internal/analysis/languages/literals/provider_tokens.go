package literals

import (
	"math"
	"regexp"
	"strings"
	"sync"
)

// TokenProvider identifies a selected credential grammar, not a live provider.
type TokenProvider string

const (
	TokenAnthropic TokenProvider = "Anthropic"
	TokenGitHub    TokenProvider = "GitHub"
	TokenGitLab    TokenProvider = "GitLab"
	TokenOpenAI    TokenProvider = "OpenAI"
	TokenSlack     TokenProvider = "Slack"
	TokenStripe    TokenProvider = "Stripe"
)

// TokenDefinition is shared by literal signatures and bounded flow analysis.
// Pattern is immutable; callers must not change its matching configuration.
type TokenDefinition struct {
	Pattern    *regexp.Regexp
	Limitation string
}

//nolint:gochecknoglobals // Compiled credential grammars are immutable across scans.
var providerTokenDefinitions = sync.OnceValue(func() map[TokenProvider]TokenDefinition {
	return map[TokenProvider]TokenDefinition{
		TokenGitHub:    {Pattern: regexp.MustCompile(`(?:gh[pous]_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{76}|github_pat_[A-Za-z0-9_]{82})`), Limitation: "Selected PAT, OAuth, user, refresh and legacy installation formats; stateless installation tokens are not recognized."},
		TokenGitLab:    {Pattern: regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,255}`), Limitation: "Default glpat- prefix only; custom instance prefixes and other GitLab token classes are not recognized."},
		TokenSlack:     {Pattern: regexp.MustCompile(`xox[bp]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[A-Za-z0-9]{20,64}`), Limitation: "Selected bot and user token formats only; app-level, session and rotated token formats are not recognized."},
		TokenStripe:    {Pattern: regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}`), Limitation: "Selected live and test secret/restricted keys; publishable pk_ keys are not credentials for this check."},
		TokenOpenAI:    {Pattern: regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{48,255}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), Limitation: "Selected project, service-account, admin and legacy key shapes; prefixes and lengths are heuristic and may change."},
		TokenAnthropic: {Pattern: regexp.MustCompile(`sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,128}`), Limitation: "Selected api03/admin01 key shapes; prefixes and lengths are heuristic and may change."},
	}
})

// ProviderToken returns a read-only built-in descriptor, or zero for an unknown provider.
func ProviderToken(provider TokenProvider) TokenDefinition {
	return providerTokenDefinitions()[provider]
}

// HasProviderToken classifies a bounded decoded value using the same boundaries,
// placeholders and payload entropy as the standalone provider-token signatures.
// Callers bound input size and account for matching work before calling it.
func HasProviderToken(text string) bool {
	for _, definition := range providerTokenDefinitions() {
		for _, at := range definition.Pattern.FindAllStringIndex(text, -1) {
			if !ProviderTokenExempt(text, at[0], at[1]) {
				return true
			}
		}
	}

	return false
}

//nolint:gochecknoglobals // Read-only token prefixes and a whole-payload placeholder grammar.
var (
	providerTokenPrefixes = strings.Fields("github_pat_ ghp_ gho_ ghu_ ghs_ ghr_ glpat- xoxb- xoxp- sk_live_ rk_live_ sk_test_ rk_test_ sk-proj- sk-svcacct- sk-admin- sk-ant-api03- sk-ant-admin01- sk-")
	providerPlaceholder   = regexp.MustCompile(`(?i)^(?:your|example|dummy|sample|test|fake|placeholder|replace|insert|redacted)(?:[_-](?:api|access|auth|key|token|secret|here|with|your|value|actual|example|placeholder|gitlab|personal|[x0]+))*$`)
)

// ProviderTokenExempt rejects boundaries, placeholders and low-entropy payloads.
func ProviderTokenExempt(text string, start, end int) bool {
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
