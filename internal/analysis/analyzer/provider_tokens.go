package analyzer

import (
	"context"
	"regexp"
	"sync"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
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
		newProviderToken(ruleSE002, literals.TokenGitHub),
		newProviderToken(ruleSE003, literals.TokenGitLab),
		newProviderToken(ruleSE004, literals.TokenSlack),
		newProviderToken(ruleSE005, literals.TokenStripe),
		newProviderToken(ruleSE006, literals.TokenOpenAI),
		newProviderToken(ruleSE007, literals.TokenAnthropic),
	}
})

func providerTokenRules() []Analyzer {
	return append([]Analyzer(nil), compiledProviderTokens()...)
}

func newProviderToken(id string, provider literals.TokenProvider) providerTokenCheck {
	definition := literals.ProviderToken(provider)

	return providerTokenCheck{
		rule: report.Rule{
			ID: id, Version: "3", Title: string(provider) + " token-shaped credential literal",
			Description: "A bounded " + string(provider) + " token shape is present in captured content.",
			Severity:    report.High, Category: "credential-material", Method: "bounded-provider-token-shape",
			Limitation: definition.Limitation + " Token boundaries, whole-secret-payload placeholders and a minimum secret-payload Shannon entropy of 3 bits/byte are checked; Slack numeric segments are excluded. Low-entropy credentials can be missed. No liveness, ownership or authorization is established. Raw bytes, supported security views and decoded structured scalars are inspected; other encodings and constructed tokens remain outside scope. Values and source excerpts are never included in findings.",
		},
		expression: definition.Pattern,
		hint:       literalFilter(definition.Pattern.String()),
	}
}

func (a providerTokenCheck) Rule() report.Rule { return a.rule }

func (providerTokenCheck) AppliesTo(document.File) bool { return true }

func (a providerTokenCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	matcher := familyAnalyzer{
		patterns: []*regexp.Regexp{a.expression},
		exempt:   literals.ProviderTokenExempt, candidateLimit: 65536,
	}
	if a.hint != nil {
		matcher.patternHints = []patternLiteralFilter{*a.hint}
	}

	return matcher.findDocument(ctx, d, budget, patternStages{})
}
