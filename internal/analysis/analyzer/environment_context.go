package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/python"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

type environmentCheck struct{ familyAnalyzer }

func (a environmentCheck) Find(ctx context.Context, doc document.File, budget int) (Result, error) {
	result, err := a.familyAnalyzer.Find(ctx, doc, budget)
	if err != nil || result.Truncated {
		return result, err
	}

	for _, unit := range doc.Units() {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		if at, ok := python.ChildEnvironmentCopy(unit); ok {
			recordChildEnvironment(&result, at, budget)
		}
	}

	return result, ctx.Err()
}

func recordChildEnvironment(result *Result, at source.Span, budget int) {
	found := false

	for i := range result.Matches {
		match := &result.Matches[i]
		if at.Start <= match.Start && match.End <= at.End {
			match.Severity = report.Low
			found = true
		}
	}

	if found {
		return
	}

	if len(result.Matches) >= budget {
		result.Truncated = true
		return
	}

	result.Matches = append(result.Matches, Match{Start: at.Start, End: at.End, Severity: report.Low})
}
