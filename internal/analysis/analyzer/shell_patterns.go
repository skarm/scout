package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
)

// shellPatterns projects cached observations or delegates language interpretation.
func (a familyAnalyzer) shellPatterns(ctx context.Context, d document.File, budget int) (Result, error) {
	if a.shellFacts != nil {
		return a.shellFacts[d.Artifact().Metadata().Path].Result(budget)
	}

	return shell.Patterns(ctx, d, shell.PatternOptions{
		Mode:          a.shellMode,
		LanguageFacts: a.languageFacts,
		MatchText: func(ctx context.Context, text string) bool {
			literal, _ := a.findText(ctx, text, 1)
			return len(literal.Matches) > 0
		},
	}, budget)
}
