package policy

import (
	"errors"
	"time"

	"github.com/skarm/scout/report"
)

// Disposition describes how one recorded observation contributes to a policy decision.
type Disposition string

const (
	DispositionBlock          Disposition = "block"
	DispositionReview         Disposition = "review"
	DispositionBelowThreshold Disposition = "below_threshold"
	DispositionSuppressed     Disposition = "suppressed"
	dispositionInvalid        Disposition = "invalid"
)

// ShadowResult compares policy outcomes over the same sealed run at one instant.
type ShadowResult struct {
	Schema                string                 `json:"schema"`
	RunDigest             string                 `json:"run_digest"`
	RunState              report.State           `json:"run_state"`
	EvaluatedAt           string                 `json:"evaluated_at"`
	Current               ShadowEvaluation       `json:"current"`
	Trial                 ShadowEvaluation       `json:"trial"`
	DecisionChanged       bool                   `json:"decision_changed"`
	FindingChanges        []FindingPolicyChange  `json:"finding_changes"`
	ManifestSignalChanges []ManifestPolicyChange `json:"manifest_signal_changes"`
}

// ShadowEvaluation includes the admission exit code the evaluated policy would produce.
type ShadowEvaluation struct {
	report.Evaluation
	ExitCode int `json:"exit_code"`
}

// FindingPolicyChange identifies a target-qualified occurrence whose policy status changed.
type FindingPolicyChange struct {
	TargetID  string          `json:"target_id"`
	FindingID string          `json:"finding_id"`
	RuleID    string          `json:"rule_id"`
	Severity  report.Severity `json:"severity"`
	Location  report.Location `json:"location"`
	Current   Disposition     `json:"current"`
	Trial     Disposition     `json:"trial"`
}

// ManifestPolicyChange identifies a manifest signal whose policy status changed.
type ManifestPolicyChange struct {
	report.ManifestSignal
	Current Disposition `json:"current"`
	Trial   Disposition `json:"trial"`
}

// Compare evaluates operator-supplied gates against a sealed run. It neither
// performs inspection nor inherits approvals from a saved evaluation.
func Compare(run report.Run, current, trial *Gate, now time.Time) (ShadowResult, error) {
	if current == nil || trial == nil || !validPolicyDigest(current.digest) || !validPolicyDigest(trial.digest) || now.IsZero() {
		return ShadowResult{}, errors.New("two valid policies and an evaluation time are required")
	}
	if err := report.ValidateSealedRun(run); err != nil {
		return ShadowResult{}, err
	}

	result := ShadowResult{
		Schema: "scout.policy-shadow/v1", RunDigest: run.Digest, RunState: run.State,
		EvaluatedAt: now.UTC().Format(time.RFC3339Nano),
		Current:     current.shadowEvaluation(run, now), Trial: trial.shadowEvaluation(run, now),
		FindingChanges: []FindingPolicyChange{}, ManifestSignalChanges: []ManifestPolicyChange{},
	}
	result.DecisionChanged = result.Current.Decision != result.Trial.Decision

	before, after := suppressionSet(result.Current.Suppressed), suppressionSet(result.Trial.Suppressed)
	for _, target := range decisionTargets(run) {
		for _, finding := range target.Analysis.Findings {
			key := occurrence{target.ID, finding.ID}
			a := current.findingDisposition(finding, before[key])
			b := trial.findingDisposition(finding, after[key])
			if a != b {
				result.FindingChanges = append(result.FindingChanges, FindingPolicyChange{
					TargetID: target.ID, FindingID: finding.ID, RuleID: finding.RuleID, Severity: finding.Severity,
					Location: finding.Location, Current: a, Trial: b,
				})
			}
		}
	}

	if run.Operation == report.CompareOperation && run.Comparison != nil && validComparisonRoles(run) {
		for _, signal := range run.Comparison.ManifestSignals {
			a, b := current.disposition(signal.Severity, true), trial.disposition(signal.Severity, true)
			if a != b {
				if signal.Before != nil {
					before := *signal.Before
					signal.Before = &before
				}
				if signal.After != nil {
					after := *signal.After
					signal.After = &after
				}
				result.ManifestSignalChanges = append(result.ManifestSignalChanges, ManifestPolicyChange{
					ManifestSignal: signal, Current: a, Trial: b,
				})
			}
		}
	}

	return result, nil
}

func (g *Gate) shadowEvaluation(run report.Run, now time.Time) ShadowEvaluation {
	evaluation := g.evaluate(run, now, true)
	code := admissionCode(run.State, run.Operation, evaluation.Decision, evaluation.PolicyDigest, validComparisonRoles(run))
	return ShadowEvaluation{Evaluation: evaluation, ExitCode: code}
}

func (g *Gate) disposition(severity report.Severity, reviewBelow bool) Disposition {
	rank := severity.Rank()
	switch {
	case rank < 0:
		return dispositionInvalid
	case rank >= g.options.FailAt.Rank():
		return DispositionBlock
	case reviewBelow:
		return DispositionReview
	default:
		return DispositionBelowThreshold
	}
}

func (g *Gate) findingDisposition(finding report.Finding, suppressed bool) Disposition {
	if suppressed {
		return DispositionSuppressed
	}
	return g.disposition(finding.Severity, g.options.ReviewBelowThreshold)
}

type occurrence struct{ targetID, findingID string }

func suppressionSet(suppressions []report.Suppression) map[occurrence]bool {
	set := make(map[occurrence]bool, len(suppressions))
	for _, suppression := range suppressions {
		set[occurrence{suppression.TargetID, suppression.FindingID}] = true
	}
	return set
}
