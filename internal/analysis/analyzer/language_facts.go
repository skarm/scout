package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/languages/golang"
	"github.com/skarm/scout/internal/analysis/languages/javascript"
	"github.com/skarm/scout/internal/analysis/languages/shell"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
)

type (
	fileLanguageFacts = check.FileLanguageFacts
	languageFacts     = check.LanguageFacts
	languageConsumer  = check.LanguageConsumer
)

func LanguageConsumers(checks []Analyzer) int {
	n := 0

	for _, a := range checks {
		if _, ok := a.(languageConsumer); ok {
			n++
		}
	}

	return n
}

// BindLanguage shares syntax/flow observations across all selected Go/Shell/JavaScript
// rules. Facts never live in Scanner or cross concurrent run boundaries.
func BindLanguage(ctx context.Context, checks []Analyzer, docs []document.File, limit int, operations uint64) []Analyzer {
	n := LanguageConsumers(checks)
	if n == 0 {
		return checks
	}

	ctx = phaseQuota(ctx, checks, n, operations)
	remaining := map[string]int{}

	for _, a := range checks {
		if _, ok := a.(languageConsumer); ok {
			remaining[a.Rule().ID] = limit
		}
	}

	facts := languageFacts{}

	for _, d := range docs {
		file := collectLanguageFacts(ctx, d, remaining)

		facts[d.Artifact().Metadata().Path] = file
		for id, rule := range file.Rules {
			remaining[id] -= rule.MatchCount()
		}
	}

	out := append([]Analyzer(nil), checks...)
	for i, a := range out {
		if consumer, ok := a.(languageConsumer); ok {
			out[i] = consumer.WithLanguageFacts(facts)
		}
	}

	return out
}

func collectLanguageFacts(ctx context.Context, doc document.File, limits map[string]int) *fileLanguageFacts {
	facts := check.NewFileLanguageFacts(limits)

	golang.Collect(ctx, doc, facts)
	shell.Collect(ctx, doc, facts)
	javascript.Collect(ctx, doc, facts)

	return facts
}
