package securitytext

import (
	"context"

	"github.com/skarm/scout/internal/syntax/source"
)

func ReconstructionWordsForTest() []string {
	words := make([]string, 0, len(reconstruction))
	for _, pattern := range reconstruction {
		words = append(words, pattern.word)
	}
	return words
}

func ReconstructForTest(ctx context.Context, text string) []source.Replacement {
	return reconstruct(ctx, text)
}

// The oracle runs every original regex in its original order, including the
// exact truncation and overlap rules; only admission differs in production.
func ReconstructionOracleForTest(text string) []source.Replacement {
	changes := make([]source.Replacement, 0)
	for _, p := range reconstruction {
		matches := p.expression.FindAllStringIndex(text, MaxChanges+1)
		if len(matches) > MaxChanges {
			return make([]source.Replacement, MaxChanges+1)
		}
		for _, at := range matches {
			matched := text[at[0]:at[1]]
			if normalized := reconstructedWord(matched); normalized != matched {
				changes = append(changes, source.Replacement{
					Span: source.Span{Start: at[0], End: at[1]},
					Text: normalized,
				})
			}
			if len(changes) > MaxChanges {
				return changes
			}
		}
	}
	return nonOverlappingChanges(changes)
}
