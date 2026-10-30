package report

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func severitySummary(findings []Finding) string {
	counts := map[Severity]int{}
	for _, finding := range findings {
		counts[finding.Severity]++
	}

	return severityCounts(counts)
}

func severityCounts(counts map[Severity]int) string {
	return fmt.Sprintf("%d critical, %d high, %d medium, %d low, %d info",
		counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info])
}

func sortedFindings(findings []Finding) []Finding {
	ordered := append([]Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Severity.Rank() > ordered[j].Severity.Rank() })

	return ordered
}

func humanTargets(run Run) []TargetResult {
	if run.Operation != CompareOperation {
		return run.Targets
	}

	targets := append([]TargetResult(nil), run.Targets...)
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Role == "after" && targets[j].Role != "after" })

	return targets
}

func approvedFindings(evaluation Evaluation) map[string]bool {
	approved := make(map[string]bool, len(evaluation.Suppressed))
	for _, entry := range evaluation.Suppressed {
		approved[entry.FindingID] = true
	}

	return approved
}

func humanSummary(out *bytes.Buffer, document Document, md bool) {
	quote := strconv.QuoteToASCII
	if md {
		quote = mdCode
	}

	_, _ = fmt.Fprintf(out, "Decision: %s. Execution: %s. Operation: %s.\n\n",
		quote(string(document.Evaluation.Decision)), quote(string(document.Run.State)), quote(string(document.Operation)))
	counts := map[State]int{}
	severities := map[Severity]int{}
	retained, approved := 0, 0

	approvals := map[string]bool{}
	for _, approval := range document.Evaluation.Suppressed {
		approvals[approval.TargetID+"\x00"+approval.FindingID] = true
	}

	for _, target := range document.Run.Targets {
		counts[target.State]++
		if document.Operation != CompareOperation || target.Role == "after" {
			for _, finding := range target.Analysis.Findings {
				retained++

				severities[finding.Severity]++
				if approvals[target.ID+"\x00"+finding.ID] {
					approved++
				}
			}
		}
	}

	_, _ = fmt.Fprintf(out, "Targets: %d total; %d complete, %d incomplete, %d failed, %d cancelled.\n\n",
		len(document.Run.Targets), counts[RunComplete], counts[RunIncomplete], counts[RunFailed], counts[RunCancelled])

	label := "Findings"
	if document.Operation == CompareOperation {
		label = "Candidate findings"
	}

	_, _ = fmt.Fprintf(out, "%s: %d retained (%s).\n\n", label, retained, severityCounts(severities))
	if approved > 0 {
		_, _ = fmt.Fprintf(out, "Operator-approved occurrences: %d; these remain visible in the findings.\n\n", approved)
	}

	if document.Run.State != RunComplete {
		out.WriteString("The requested inspection did not finish completely. Missing findings cannot establish a clean result.\n\n")
	}

	if md {
		out.WriteString("## Why this decision\n\n")
	} else {
		out.WriteString("Why this decision:\n")
	}

	for _, reason := range document.Evaluation.Reasons {
		_, _ = fmt.Fprintf(out, "- %s (%s).\n", decisionReason(reason), quote(reason))
	}

	if len(document.Evaluation.Reasons) == 0 {
		out.WriteString("No policy reason was supplied by the evaluator.\n")
	}

	out.WriteString("\n")
}

func decisionReason(code string) string {
	switch code {
	case "policy_allowed":
		return "The selected work completed and the evaluated policy allows admission within that scope"
	case "finding_threshold", "severity_threshold":
		return "At least one unsuppressed finding meets the configured blocking threshold"
	case "inspection_incomplete":
		return "Some requested work failed, was cancelled or left a coverage gap"
	case "selected_scope_limitations_require_review":
		return "The conservative coverage policy requires manual review of declared language-analysis limitations"
	case "changed_content_requires_review":
		return "Captured content changed between versions and requires review"
	case "manifest_signal_threshold":
		return "A declaration change meets the configured blocking threshold"
	case "manifest_signals_require_review":
		return "Security-relevant declaration changes require manual review"
	case "semantic_proposals_require_review":
		return "The reviewer produced evidence-linked hypotheses that require manual review"
	case "previous_semantic_proposals_require_review":
		return "The previous version contains reviewer hypotheses that require manual review"
	case "findings_below_threshold_require_review":
		return "The policy requires manual review of findings below the blocking threshold"
	case "pending_approvals":
		return "The baseline contains pending operator approvals"
	case "baseline_identity_mismatch":
		return "The baseline does not match this engine, profile or rulepack"
	case "baseline_application_failed":
		return "The supplied baseline could not be applied"
	default:
		return "Additional policy reason reported by the evaluator"
	}
}

func writeHumanDiagnostics(b *strings.Builder, diagnostics []Diagnostic, md bool) {
	quote := strconv.QuoteToASCII

	prefix := "\n"
	if md {
		quote, prefix = mdCode, "### "
	}

	for _, scope := range []bool{true, false} {
		heading := "Coverage gaps"
		if !scope {
			heading = "Analysis notes"
		}

		written := false

		for _, d := range diagnostics {
			if d.AffectsScope != scope {
				continue
			}

			if !written {
				_, _ = fmt.Fprintf(b, "%s%s\n\n", prefix, heading)
				written = true
			}

			_, _ = fmt.Fprintf(b, "- %s", quote(d.Code))
			if d.Path != "" {
				_, _ = fmt.Fprintf(b, " at %s", quote(d.Path))
			}

			_, _ = fmt.Fprintf(b, ": %s\n", quote(d.Message))
		}

		if written {
			b.WriteString("\n")
		}
	}
}

func writeValidationSummary(b *strings.Builder, validation ValidationReport, md bool) {
	quote := strconv.QuoteToASCII
	if md {
		quote = mdCode
	}

	_, _ = fmt.Fprintf(b, "Validation tasks: %d planned; %d recorded outcomes; status: %s.\n\n",
		len(validation.Tasks), len(validation.Outcomes), quote(string(validation.Completeness)))
	counts := map[string]int{}

	outcomes := make(map[string]TaskOutcome, len(validation.Outcomes))
	for _, outcome := range validation.Outcomes {
		counts[outcome.Status]++
		outcomes[outcome.TaskID] = outcome
	}

	statuses := make([]string, 0, len(counts))
	for status := range counts {
		statuses = append(statuses, status)
	}

	sort.Strings(statuses)

	for _, status := range statuses {
		_, _ = fmt.Fprintf(b, "Task outcomes %s: %d.\n", quote(status), counts[status])
	}

	b.WriteString("\n")

	for _, task := range validation.Tasks {
		outcome, found := outcomes[task.ID]
		if !task.Required || completedCheck(outcome.Status) {
			continue
		}

		if !found {
			outcome.Status = OutcomeMissing
		}

		_, _ = fmt.Fprintf(b, "- Required task %s", quote(task.Kind))
		if task.AnalyzerID != "" {
			_, _ = fmt.Fprintf(b, " / %s", quote(task.AnalyzerID))
		}

		if task.Path != "" {
			_, _ = fmt.Fprintf(b, " at %s", quote(task.Path))
		}

		_, _ = fmt.Fprintf(b, ": %s", quote(outcome.Status))
		if outcome.Reason != "" {
			_, _ = fmt.Fprintf(b, " (%s)", quote(outcome.Reason))
		}

		b.WriteString(".\n")
	}

	if validation.OmittedTasks > 0 {
		_, _ = fmt.Fprintf(b, "Tasks omitted by the planning limit: %d.\n", validation.OmittedTasks)
	}

	b.WriteString("\n")
}
