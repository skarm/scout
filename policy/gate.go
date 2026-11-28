// Package policy applies trusted operator decisions to sealed inspection runs.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/report"
)

const (
	maxPolicyIDBytes = 128
)

// Options are operator-owned policy settings. A report's stored policy or
// suppression records never substitute for these explicitly supplied approvals.
type Options struct {
	// ID names the trusted policy; New supplies strict-v1 when it is empty.
	ID string `json:"id"`
	// FailAt sets the minimum unsuppressed finding severity that blocks admission.
	FailAt report.Severity `json:"fail_at"`
	// Approvals supplies trusted baseline entries; nil applies no approvals.
	Approvals *baseline.Document `json:"approvals,omitempty"`
	// ApprovedSnapshotSHA256 is a trusted comparison candidate approval.
	ApprovedSnapshotSHA256 string `json:"approved_snapshot_sha256,omitempty"`
	// AllowGlobs permits glob approvals only when explicitly selected by the operator.
	AllowGlobs bool `json:"allow_globs"`
	// ReviewBelowThreshold requires review for unsuppressed findings below FailAt.
	ReviewBelowThreshold bool `json:"review_below_threshold"`
	// Scope controls declared language limitations; an empty value selects ConservativeScope.
	Scope ScopePolicy `json:"scope"`
}

// ScopePolicy separates successful selected checks from exhaustive language
// coverage. Conservative keeps those declared limitations a review obligation.
type ScopePolicy string

const (
	// ConservativeScope requires review for declared limitations in supported
	// language semantics.
	ConservativeScope ScopePolicy = "conservative"
	// SelectedScope accepts declared language limitations when the selected work
	// completes. It does not waive execution gaps.
	SelectedScope ScopePolicy = "selected"
)

// Gate is immutable after construction and safe for concurrent evaluations.
type Gate struct {
	options Options
	digest  string
}

type gateEvaluation struct {
	evaluation report.Evaluation
	reasons    map[string]struct{}
}

// New validates and copies the complete policy before any run is evaluated.
func New(options Options) (*Gate, error) {
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}

	if options.Approvals != nil {
		approvals, err := copyApprovals(*options.Approvals, options.AllowGlobs)
		if err != nil {
			return nil, err
		}

		options.Approvals = &approvals
	}

	encoded, err := json.Marshal(struct {
		Version string  `json:"version"`
		Options Options `json:"options"`
	}{
		Version: "gate-v1",
		Options: options,
	})
	if err != nil {
		return nil, errors.New("policy cannot be encoded")
	}

	digest := sha256.Sum256(encoded)

	return &Gate{options: options, digest: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

// Code is the machine contract shared by CLI output formats. Invalid documents
// and incomplete execution take precedence over any finding or policy decision.
func Code(document report.Document) int {
	if document.Validate() != nil {
		return 2
	}

	return admissionCode(document.Run.State, document.Operation, document.Evaluation.Decision, document.Evaluation.PolicyDigest, validComparisonRoles(document.Run))
}

// PreparedCode maps a verified immutable document without repeating digest work.
func PreparedCode(document report.PreparedDocument) int {
	if !document.Valid() {
		return 2
	}

	return admissionCode(document.State(), document.Operation(), document.Decision(), document.PolicyDigest(), document.ValidComparisonRoles())
}

// Evaluate applies policy to the run's unchanged observations at an explicit
// trusted time. Invalid or unfinished execution can never authorize admission;
// a blocking finding remains blocking even when execution is incomplete.
func (g *Gate) Evaluate(run report.Run, now time.Time) report.Evaluation {
	return g.evaluate(run, now, report.ValidateSealedRun(run) == nil)
}

func (g *Gate) evaluate(run report.Run, now time.Time, valid bool) report.Evaluation {
	result := gateEvaluation{evaluation: report.Evaluation{
		Decision: report.Allow, RunDigest: run.Digest,
		Reasons: []string{}, Suppressed: []report.Suppression{},
	}, reasons: make(map[string]struct{})}
	if g == nil || !validPolicyDigest(g.digest) {
		result.review("invalid_policy")
		return result.evaluation
	}

	result.evaluation.PolicyDigest = g.digest
	validateEvaluationRun(run, valid, &result)

	if run.Operation == report.CompareOperation {
		g.evaluateComparison(run, valid, &result)
	}

	for _, target := range decisionTargets(run) {
		g.evaluateTarget(target, now, &result)
	}

	if run.Environment != nil {
		for _, observation := range run.Environment.Observations {
			if observation.Kind != report.EnvironmentSkillReference {
				result.review("environment_observations_require_review")
			}
		}
	}

	if len(result.evaluation.Reasons) == 0 {
		result.add("policy_allowed")
	}

	return result.evaluation
}

func (g *Gate) evaluateComparison(run report.Run, valid bool, result *gateEvaluation) {
	if !validComparisonRoles(run) {
		return
	}

	if run.Comparison == nil {
		return
	}

	approved := g.evaluatePackageApproval(run, valid, result)
	if !approved && !run.Comparison.SameSnapshot {
		result.review("changed_content_requires_review")
	}

	if len(run.Targets[0].Analysis.Semantic.Proposals) != 0 {
		result.review("previous_semantic_proposals_require_review")
	}

	if len(run.Comparison.MCPChanges) > 0 {
		result.review("mcp_declarations_require_review")
	}

	for _, signal := range run.Comparison.ManifestSignals {
		switch g.disposition(signal.Severity, true) {
		case dispositionInvalid:
			result.review("invalid_manifest_signal_severity")
		case DispositionBlock:
			result.evaluation.Decision = report.Block
			result.add("manifest_signal_threshold")
		default:
			result.review("manifest_signals_require_review")
		}
	}
}

func (g *Gate) evaluatePackageApproval(run report.Run, valid bool, result *gateEvaluation) bool {
	if g.options.ApprovedSnapshotSHA256 == "" {
		return false
	}

	if !valid || run.State != report.RunComplete {
		result.review("package_approval_unverified")
		return false
	}

	for _, target := range run.Targets {
		artifact := target.Analysis.Artifact
		if !artifact.InventoryComplete || target.Analysis.External != nil ||
			!validPolicyDigest("sha256:"+artifact.SnapshotSHA256) || len(artifact.ExcludeGlobs) != 0 ||
			artifact.IdentityScope != report.CapturedContentIdentity ||
			len(artifact.Files) == 0 || !allFilesCaptured(artifact.Files) {
			result.review("package_approval_unverified")
			return false
		}
	}

	if run.Targets[1].Analysis.Artifact.SnapshotSHA256 != g.options.ApprovedSnapshotSHA256 {
		result.review("package_approval_hash_mismatch")
		return false
	}

	result.add("package_approval_hash_matched")

	return true
}

func allFilesCaptured(files []report.File) bool {
	for _, file := range files {
		if file.Status != report.CaptureCaptured {
			return false
		}
	}

	return true
}

func (g *Gate) evaluateTarget(target report.TargetResult, now time.Time, result *gateEvaluation) {
	analysis := target.Analysis
	g.evaluateScope(analysis, result)

	for _, finding := range analysis.Findings {
		if finding.Severity.Rank() < 0 {
			result.review("invalid_finding_severity")
		}
	}

	for _, finding := range g.activeFindings(target, now, result) {
		g.evaluateFinding(finding, result)
	}

	if len(analysis.Semantic.Proposals) != 0 {
		result.review("semantic_proposals_require_review")
	}
}

func (g *Gate) evaluateScope(analysis report.Analysis, result *gateEvaluation) {
	if g.options.Scope == ConservativeScope {
		for _, diagnostic := range analysis.Diagnostics {
			if !diagnostic.AffectsScope && strings.HasSuffix(diagnostic.Code, "_semantics_limited") {
				result.review("selected_scope_limitations_require_review")
				break
			}
		}
	}
}

func (g *Gate) activeFindings(target report.TargetResult, now time.Time, result *gateEvaluation) []report.Finding {
	analysis := target.Analysis

	active := analysis.Findings
	if g.options.Approvals != nil {
		applied, remaining, err := baseline.Apply(analysis, *g.options.Approvals, now, g.options.AllowGlobs)
		if err != nil {
			result.review("baseline_application_failed")
		} else {
			active = remaining

			for i := range applied.Suppressed {
				applied.Suppressed[i].TargetID = target.ID
			}

			result.evaluation.Suppressed = append(result.evaluation.Suppressed, applied.Suppressed...)
			if applied.Pending != 0 {
				result.review("pending_approvals")
			}

			if applied.Status == "identity_mismatch" {
				result.review("baseline_identity_mismatch")
			}
		}
	}

	return active
}

func (g *Gate) evaluateFinding(finding report.Finding, result *gateEvaluation) {
	switch g.disposition(finding.Severity, g.options.ReviewBelowThreshold) {
	case dispositionInvalid:
		result.review("invalid_finding_severity")
	case DispositionBlock:
		result.evaluation.Decision = report.Block
		result.add("finding_threshold")
	case DispositionReview:
		result.review("findings_below_threshold_require_review")
	}
}

// Normalize passive settings before taking ownership of approvals or computing
// identity. Validation order is part of the constructor's error contract.
func (o Options) normalized() (Options, error) {
	if o.Scope == "" {
		o.Scope = ConservativeScope
	}

	if o.Scope != ConservativeScope && o.Scope != SelectedScope {
		return Options{}, errors.New("invalid scope policy")
	}

	if o.ID == "" {
		o.ID = "strict-v1"
	}

	if len(o.ID) > maxPolicyIDBytes || o.FailAt.Rank() < 0 {
		return Options{}, errors.New("invalid policy ID or blocking threshold")
	}

	if o.ApprovedSnapshotSHA256 != "" && !validPolicyDigest("sha256:"+o.ApprovedSnapshotSHA256) {
		return Options{}, errors.New("approved package SHA-256 must be 64 lowercase hexadecimal digits")
	}

	return o, nil
}

func copyApprovals(document baseline.Document, allowGlobs bool) (baseline.Document, error) {
	if err := baseline.Validate(document); err != nil {
		return baseline.Document{}, err
	}

	for _, entry := range document.Entries {
		if entry.Kind == baseline.KindGlob && !allowGlobs {
			return baseline.Document{}, errors.New("glob approvals require explicit permission")
		}
	}

	entries := make([]baseline.Entry, len(document.Entries))
	copy(entries, document.Entries)
	document.Entries = entries

	return document, nil
}

func validateEvaluationRun(run report.Run, valid bool, result *gateEvaluation) {
	if !valid {
		result.review("invalid_run")
	}

	if run.State != report.RunComplete {
		result.review("inspection_incomplete")
	}

	if run.Operation == report.CompareOperation && !validComparisonRoles(run) {
		result.review("invalid_comparison_roles")
	}
}

func validComparisonRoles(run report.Run) bool {
	return len(run.Targets) == 2 && run.Targets[0].Role == "before" && run.Targets[1].Role == "after"
}

func decisionTargets(run report.Run) []report.TargetResult {
	if run.Operation != report.CompareOperation {
		return run.Targets
	}

	if validComparisonRoles(run) {
		return run.Targets[1:]
	}

	return nil
}

func (result *gateEvaluation) review(reason string) {
	if result.evaluation.Decision == report.Allow {
		result.evaluation.Decision = report.Review
	}

	result.add(reason)
}

func (result *gateEvaluation) add(reason string) {
	if _, exists := result.reasons[reason]; !exists {
		result.reasons[reason] = struct{}{}
		result.evaluation.Reasons = append(result.evaluation.Reasons, reason)
	}
}

func admissionCode(state report.State, operation report.Operation, decision report.Decision, policyDigest string, comparisonRoles bool) int {
	if !validPolicyDigest(policyDigest) {
		return 2
	}

	if operation == report.CompareOperation && !comparisonRoles {
		return 2
	}

	if state != report.RunComplete {
		return 2
	}

	if decision != report.Allow {
		return 1
	}

	return 0
}

func validPolicyDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}

	hexValue := strings.TrimPrefix(value, prefix)
	_, err := hex.DecodeString(hexValue)

	return err == nil && hexValue == strings.ToLower(hexValue)
}
