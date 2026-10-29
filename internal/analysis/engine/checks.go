package engine

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/validation"
	"github.com/skarm/scout/report"
)

func (e *Engine) runCheck(ctx context.Context, a check.Analyzer, rule report.Rule, files []document.File, byPath map[string]document.File, budget int, plan *validation.Ledger) (out outcome) {
	out.check = report.Check{AnalyzerID: rule.ID, Version: rule.Version, Status: report.OutcomeCompleted}

	// Panic text is untrusted and can contain source content. Do not leak it.
	defer func() {
		out.check.Findings = len(out.findings)
		if recover() != nil {
			out.check.Status = report.OutcomeFailed
			out.check.Detail = "Analyzer panic; existing findings retained."
			out.diagnostics = append(out.diagnostics, report.Diagnostic{
				Code:         "analyzer_panic",
				Message:      rule.ID + ": analyzer failed.",
				AffectsScope: true,
			})
		}

		for i := range out.fileChecks {
			if out.fileChecks[i].Status == "running" {
				out.fileChecks[i].Status = report.OutcomeFailed
			}
		}
	}()

	out.planFiles(a, rule, files, plan)

	if out.check.FilesTotal == 0 {
		out.check.Status = report.OutcomeNotApplicable
		return out
	}

	for i, doc := range files {
		f := doc.Artifact()

		switch out.fileChecks[i].Status {
		case report.OutcomeNotApplicable, "not_planned":
			continue
		}

		if err := ctx.Err(); err != nil {
			out.check.Status = report.OutcomeCancelled
			out.fileChecks[i].Status = report.OutcomeCancelled

			return out
		}

		if !analysisbudget.Consume(ctx, 1) {
			out.check.Status = report.OutcomePartial
			out.fileChecks[i].Status = report.OutcomePartial
			out.diagnostics = append(out.diagnostics, report.Diagnostic{
				Code:         "operation_limit",
				Path:         f.Metadata().Path,
				Message:      rule.ID + ": analysis operation budget exhausted.",
				AffectsScope: true,
			})

			return out
		}

		var (
			result check.Result
			err    error
		)

		out.fileChecks[i].Status = "running"
		result, err = a.Find(ctx, doc, budget-len(out.findings))

		acceptAnalyzerResult(&out, rule, doc, result, err, byPath, budget, i)
	}

	out.check.Findings = len(out.findings)

	return out
}

func acceptAnalyzerResult(out *outcome, rule report.Rule, doc document.File, result check.Result, err error, byPath map[string]document.File, budget, index int) {
	f := doc.Artifact()

	failed := err != nil
	if err != nil {
		out.check.Status = report.OutcomeFailed
		out.diagnostics = append(out.diagnostics, report.Diagnostic{
			Code:         "analyzer_failed",
			Path:         f.Metadata().Path,
			Message:      rule.ID + ": analyzer returned an error; results are incomplete.",
			AffectsScope: true,
		})
		// A partial result may carry valid evidence from before the failure.
		// Validate and retain it; never silently turn it into an empty result.
	}

	if len(result.Matches) > budget-len(out.findings) {
		out.check.Status = report.OutcomeFailed
		out.diagnostics = append(out.diagnostics, report.Diagnostic{
			Code:         "analyzer_contract",
			Path:         f.Metadata().Path,
			Message:      rule.ID + ": analyzer exceeded its result budget.",
			AffectsScope: true,
		})
		result.Matches = result.Matches[:budget-len(out.findings)]
		failed = true
	}

	valid := out.appendMatches(rule, doc, result.Matches, byPath)

	if result.Truncated {
		if out.check.Status != report.OutcomeFailed {
			out.check.Status = report.OutcomePartial
		}

		out.diagnostics = append(out.diagnostics, report.Diagnostic{
			Code:         "finding_limit",
			Path:         f.Metadata().Path,
			Message:      rule.ID + ": additional matches omitted at the finding budget.",
			AffectsScope: true,
		})
	}

	switch {
	case failed || !valid:
		out.fileChecks[index].Status = report.OutcomeFailed
	case result.Truncated:
		out.fileChecks[index].Status = report.OutcomePartial
	default:
		out.fileChecks[index].Status = report.OutcomeCompleted
		out.check.FilesDone++
	}
}

func (out *outcome) planFiles(a check.Analyzer, rule report.Rule, files []document.File, plan *validation.Ledger) {
	out.fileChecks = make([]report.FileCheck, len(files))
	for i := range files {
		out.fileChecks[i] = report.FileCheck{AnalyzerID: rule.ID, Status: report.OutcomeNotRun}
	}

	for i, f := range files {
		if !plan.Scheduled(rule.ID, f.Artifact().Metadata().Path) {
			out.fileChecks[i].Status = "not_planned"
			out.check.Status = report.OutcomePartial

			continue
		}

		if a.AppliesTo(f) {
			out.check.FilesTotal++
		} else {
			out.fileChecks[i].Status = report.OutcomeNotApplicable
		}
	}
}

func (out *outcome) appendMatches(rule report.Rule, doc document.File, matches []check.Match, byPath map[string]document.File) bool {
	valid := true

	for _, m := range matches {
		finding, err := makeFinding(rule, doc, m)
		if err == nil {
			err = attachRelated(&finding, m.Related, byPath)
		}

		if err != nil {
			valid = false
			out.check.Status = report.OutcomeFailed
			out.diagnostics = append(out.diagnostics, report.Diagnostic{
				Code:         "invalid_evidence",
				Path:         doc.Artifact().Metadata().Path,
				Message:      rule.ID + ": invalid source coordinates rejected.",
				AffectsScope: true,
			})

			continue
		}

		out.findings = append(out.findings, finding)
	}

	return valid
}
