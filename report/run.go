package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
)

// State describes execution, independently of finding severity and policy.
type State string

const (
	// Unknown is the zero execution state and is not a valid sealed-run state.
	Unknown State = ""
	// RunComplete means every requested target completed the selected work.
	RunComplete State = "complete"
	// RunIncomplete means selected work or retained observations are incomplete.
	RunIncomplete State = "incomplete"
	// RunFailed means execution failed.
	RunFailed State = "failed"
	// RunCancelled means execution stopped because its context was cancelled or
	// expired.
	RunCancelled State = "cancelled"
)

// Operation distinguishes scans from comparisons in the report envelope.
type Operation string

const (
	// ScanOperation identifies a scan of one or more requested targets.
	ScanOperation Operation = "scan"
	// CompareOperation identifies fresh before and after scans with an update
	// delta.
	CompareOperation Operation = "compare"
)

// EngineIdentity identifies the Scout build and selected rulepack.
type EngineIdentity struct {
	// Version records the Scout module version or explicit build override.
	Version string `json:"version"`
	// RulepackDigest binds selected checks and rule data; it is not a hash of the
	// whole analyzer implementation.
	RulepackDigest string `json:"rulepack_digest"`
}

// Run retains every requested target in input order. Its digest binds stable
// observations; it is not an attestation that the observations are authentic.
type Run struct {
	// State records execution status independently of policy and finding severity.
	State State `json:"state"`
	// Digest binds the stable observations in the sealed run without attesting
	// their authenticity.
	Digest string `json:"digest"`
	// Engine records the build and selected rulepack identity.
	Engine EngineIdentity `json:"engine"`
	// Plan describes the work selected before execution.
	Plan InspectionPlan `json:"plan"`
	// Targets retains every requested input occurrence and its result in original
	// input order.
	Targets []TargetResult `json:"targets"`
	// Problems records structured execution failures affecting the run.
	Problems []Problem `json:"problems"`
	// Comparison contains the bounded delta for a comparison, and is nil for a
	// scan.
	Comparison *UpdateDelta `json:"comparison,omitempty"`
	// Environment is present only after an explicitly selected joint analysis.
	Environment *EnvironmentReport `json:"environment,omitempty"`
	// Operation identifies whether this result represents a scan or comparison.
	Operation Operation `json:"-"`
}

// TargetResult retains one requested input, its execution state and its
// analysis at the original input index.
type TargetResult struct {
	// ID identifies this requested target occurrence independently of its label.
	ID string `json:"id"`
	// Index is the target's zero-based position in the original request.
	Index int `json:"index"`
	// Role is before or after for comparison targets and empty for ordinary scans.
	Role string `json:"role,omitempty"`
	// Label retains the caller-supplied input label.
	Label string `json:"label,omitempty"`
	// State records execution status independently of policy and finding severity.
	State State `json:"state"`
	// Analysis contains passive observations for this target.
	Analysis Analysis `json:"analysis"`
}

// Problem records a structured execution failure without copying arbitrary
// provider error text.
type Problem struct {
	// Code is a stable machine-readable condition identifier.
	Code string `json:"code"`
	// Phase identifies the execution phase in which the problem occurred.
	Phase string `json:"phase"`
	// TargetID identifies the target affected by this execution problem, when
	// applicable.
	TargetID string `json:"target_id,omitempty"`
	// ObjectID identifies the affected captured or derived object, when
	// applicable.
	ObjectID string `json:"object_id,omitempty"`
	// Message contains a bounded explanation without copying source secrets.
	Message string `json:"message,omitempty"`
	// Retryable reports whether the structured problem permits retry
	// interpretation.
	Retryable bool `json:"retryable"`
}

// Evaluation binds a trusted policy decision and approvals to a sealed run
// digest.
type Evaluation struct {
	// Decision records the trusted policy outcome.
	Decision Decision `json:"decision"`
	// RunDigest binds the evaluation to the sealed run it evaluated.
	RunDigest string `json:"run_digest"`
	// PolicyDigest identifies the trusted policy configuration used for
	// evaluation.
	PolicyDigest string `json:"policy_digest"`
	// Reasons lists policy reason codes supporting Decision.
	Reasons []string `json:"reasons"`
	// Suppressed records applied operator approvals without removing observations
	// from the run.
	Suppressed []Suppression `json:"suppressed"`
}

// Document combines a sealed run and its policy evaluation under the versioned
// report schema.
type Document struct {
	// Schema identifies the versioned report envelope.
	Schema string `json:"schema"`
	// Operation identifies whether this result represents a scan or comparison.
	Operation Operation `json:"operation"`
	// Run contains the sealed execution observations.
	Run Run `json:"run"`
	// Evaluation contains the policy decision bound to Run.
	Evaluation Evaluation `json:"evaluation"`
}

// NewDocument combines a run and its evaluation without validating or sealing
// them. Use Prepare before rendering.
func NewDocument(run Run, evaluation Evaluation) Document {
	return Document{Schema: DocumentSchema, Operation: run.Operation, Run: run, Evaluation: evaluation}
}

// SealRun validates self-consistency and returns an independent result with a
// deterministic digest. Caller-owned slices and pointers are neither reordered
// nor retained. Labels and acquisition metadata remain in the returned result.
func SealRun(run Run) (Run, error) {
	if err := validateRun(run); err != nil {
		return Run{}, err
	}

	snapshot := copyReport(run)

	digest, err := runDigest(snapshot)
	if err != nil {
		return Run{}, err
	}

	snapshot.Digest = digest

	return snapshot, nil
}

// ValidateSealedRun checks observations and their binding without copying the
// report. Mutable values are never cached or presumed unchanged across calls.
func ValidateSealedRun(run Run) error {
	if err := validateRun(run); err != nil {
		return err
	}

	digest, err := runDigest(run)
	if err != nil {
		return err
	}

	if run.Digest == "" || digest != run.Digest {
		return errors.New("report digest does not match run")
	}

	return nil
}

// Validate rejects altered runs, mismatched evaluations and incomplete allows.
// Operation is supplied by the envelope after a normal JSON round trip, because
// Run deliberately does not serialize another copy of that discriminator.
func (d Document) Validate() error {
	_, err := d.validated()
	return err
}

// Validation resolves legacy per-analysis approvals once, before a prepared
// document is rendered. An ambiguous occurrence cannot choose its own target.
func (d Document) validated() (Document, error) {
	if d.Schema != DocumentSchema {
		return Document{}, errors.New("unsupported report schema")
	}

	if d.Run.Operation != "" && d.Run.Operation != d.Operation {
		return Document{}, errors.New("report operation disagrees with run")
	}

	run := d.Run
	run.Operation = d.Operation

	if err := ValidateSealedRun(run); err != nil {
		return Document{}, err
	}

	if d.Evaluation.RunDigest != run.Digest {
		return Document{}, errors.New("report or evaluation digest does not match run")
	}

	if err := validateDecision(d.Evaluation.Decision, run.State); err != nil {
		return Document{}, err
	}

	return d.scopeSuppressions()
}

func (d Document) scopeSuppressions() (Document, error) {
	if len(d.Evaluation.Suppressed) == 0 {
		return d, nil
	}

	targets := make(map[string]map[string]bool)

	for _, target := range d.Run.Targets {
		for _, finding := range target.Analysis.Findings {
			if targets[finding.ID] == nil {
				targets[finding.ID] = make(map[string]bool)
			}

			targets[finding.ID][target.ID] = true
		}
	}

	d.Evaluation.Suppressed = append([]Suppression(nil), d.Evaluation.Suppressed...)
	for i := range d.Evaluation.Suppressed {
		approval := &d.Evaluation.Suppressed[i]

		matches := targets[approval.FindingID]
		if approval.TargetID != "" {
			if !matches[approval.TargetID] {
				return Document{}, errors.New("suppression references an unknown target or finding")
			}

			continue
		}

		if len(matches) > 1 {
			return Document{}, errors.New("suppression requires an unambiguous target")
		}

		for id := range matches {
			approval.TargetID = id
		}
	}

	return d, nil
}

func validateDecision(decision Decision, state State) error {
	switch decision {
	case Allow:
		if state != RunComplete {
			return errors.New("incomplete execution cannot allow")
		}
	case Review, Block:
	default:
		return errors.New("unknown policy decision")
	}

	return nil
}

func validateRun(run Run) error {
	if !knownState(run.State) || len(run.Targets) == 0 {
		return errors.New("run requires a known state and explicit targets")
	}

	if err := validateOperation(run); err != nil {
		return err
	}

	if err := validateTargets(run.Targets); err != nil {
		return err
	}

	if err := validateEnvironment(run); err != nil {
		return err
	}

	if run.State == RunComplete {
		if len(run.Problems) != 0 {
			return errors.New("complete run contains execution problems")
		}

		for _, target := range run.Targets {
			if target.State != RunComplete {
				return errors.New("complete run contains unfinished target")
			}
		}
	}

	return nil
}

func validateTargets(targets []TargetResult) error {
	seen := make(map[string]bool, len(targets))
	for i, target := range targets {
		if target.ID == "" || seen[target.ID] || target.Index != i || !knownState(target.State) {
			return fmt.Errorf("invalid target identity, index or state at %d", i)
		}

		seen[target.ID] = true
		if target.State == RunComplete {
			if err := validateCompleteAnalysis(target.Analysis); err != nil {
				return fmt.Errorf("target %d: %w", i, err)
			}
		}
	}

	return nil
}

func validateOperation(run Run) error {
	switch run.Operation {
	case ScanOperation:
		if run.Comparison != nil {
			return errors.New("scan cannot contain comparison changes")
		}
	case CompareOperation:
		if len(run.Targets) != 2 || run.Comparison == nil {
			return errors.New("comparison requires two fresh targets and changes")
		}

		if run.State == RunComplete && !completeComparison(*run.Comparison) {
			return errors.New("complete run contains incomplete comparison")
		}
	default:
		return errors.New("unknown run operation")
	}

	return nil
}

func completeComparison(changes UpdateDelta) bool {
	return changes.Completeness == Complete && changes.OmittedChanges == 0 && len(changes.Issues) == 0
}

func knownState(state State) bool {
	switch state {
	case RunComplete, RunIncomplete, RunFailed, RunCancelled:
		return true
	default:
		return false
	}
}

func validateCompleteAnalysis(r Analysis) error {
	if r.Coverage.Completeness != Complete {
		return errors.New("complete target requires complete coverage")
	}

	for _, diagnostic := range r.Diagnostics {
		if diagnostic.AffectsScope {
			return errors.New("complete target contains a scope gap")
		}
	}

	if err := validateCompleteCoverage(r.Coverage); err != nil {
		return err
	}

	if err := validateCompleteTasks(r.Validation); err != nil {
		return err
	}

	return validateCompleteServices(r)
}

func validateCompleteTasks(validation ValidationReport) error {
	if validation.Completeness != "" && validation.Completeness != Complete {
		return errors.New("complete target contains incomplete task validation")
	}

	if validation.OmittedTasks != 0 || len(validation.Issues) != 0 {
		return errors.New("complete target contains task validation gaps")
	}

	planned, err := indexValidationTasks(validation.Tasks)
	if err != nil {
		return err
	}

	return validateTaskOutcomes(planned, validation.Outcomes)
}

func indexValidationTasks(tasks []AnalysisTask) (map[string]bool, error) {
	planned := make(map[string]bool, len(tasks))
	for _, task := range tasks {
		if err := addPlannedTask(planned, task.ID, task.Required); err != nil {
			return nil, fmt.Errorf("complete task validation contains %w", err)
		}
	}

	return planned, nil
}

func addPlannedTask(planned map[string]bool, id string, required bool) error {
	if _, duplicate := planned[id]; id == "" || duplicate {
		return errors.New("invalid task identities")
	}

	planned[id] = required

	return nil
}

func validateTaskOutcomes(planned map[string]bool, outcomes []TaskOutcome) error {
	for _, outcome := range outcomes {
		required, pending := planned[outcome.TaskID]
		if !pending || !completedTask(outcome.Status, required) {
			return errors.New("complete task validation contains an invalid or unfinished outcome")
		}

		delete(planned, outcome.TaskID)
	}

	return validateNoPendingTasks(planned, "complete task validation")
}

func validateNoPendingTasks(planned map[string]bool, scope string) error {
	if len(planned) != 0 {
		return fmt.Errorf("%s has missing outcomes", scope)
	}

	return nil
}

func completedTask(status string, required bool) bool {
	return completedCheck(status) || !required && status == OutcomeDisabled
}

func validateCompleteCoverage(coverage Coverage) error {
	for _, check := range coverage.Checks {
		if !completedCheck(check.Status) {
			return errors.New("complete coverage contains unfinished check")
		}
	}

	for _, file := range coverage.Files {
		if file.Completeness != Complete || len(file.Gaps) != 0 {
			return errors.New("complete coverage contains incomplete object")
		}

		for _, check := range file.Checks {
			if !completedCheck(check.Status) {
				return errors.New("complete object contains unfinished check")
			}
		}
	}

	return nil
}

func completedCheck(status string) bool {
	switch status {
	case OutcomeCompleted, OutcomeNotApplicable, OutcomeCached:
		return true
	default:
		return false
	}
}

func validateCompleteServices(r Analysis) error {
	if r.External != nil {
		if !r.External.Complete {
			return errors.New("complete target contains incomplete external traversal")
		}

		for _, ref := range r.External.References {
			if ref.Status != CaptureCaptured && ref.Status != CaptureAlreadyCaptured {
				return errors.New("complete target contains unfinished external source")
			}
		}
	}

	if r.Metadata.Completeness != "" && r.Metadata.Completeness != Complete {
		return errors.New("complete target contains incomplete metadata")
	}

	for _, manifest := range r.Dependencies.Manifests {
		if !manifest.InventoryComplete() {
			return errors.New("complete target contains incomplete dependency inventory")
		}
	}

	if err := validateCompleteSignatures(r.Signatures); err != nil {
		return err
	}

	if r.Vulnerabilities.Enabled && r.Vulnerabilities.Completeness != Complete {
		return errors.New("complete target contains incomplete dependency lookup")
	}

	return validateCompleteSemantic(r.Semantic)
}

func validateCompleteSignatures(signatures SignatureReport) error {
	if !signatures.Enabled {
		return nil
	}

	if signatures.Completeness != string(Complete) {
		return errors.New("complete target contains incomplete signatures")
	}

	for _, outcome := range signatures.Outcomes {
		if outcome.Status != OutcomeCompleted || outcome.Truncated {
			return errors.New("complete target contains unfinished signature outcome")
		}
	}

	return nil
}

func validateCompleteSemantic(semantic SemanticReport) error {
	if !semantic.Enabled {
		return nil
	}

	if semantic.Completeness != Complete || len(semantic.Gaps) != 0 || semantic.OmittedGaps != 0 {
		return errors.New("complete target contains incomplete semantic review")
	}

	if semantic.CompletedRequests != len(semantic.Outcomes) {
		return errors.New("complete semantic review has inconsistent request accounting")
	}

	planned, err := indexSemanticTasks(semantic.Tasks)
	if err != nil {
		return err
	}

	return validateSemanticOutcomes(planned, semantic.Outcomes)
}

func indexSemanticTasks(tasks []SemanticTask) (map[string]bool, error) {
	planned := make(map[string]bool, len(tasks))
	for _, task := range tasks {
		if err := addPlannedTask(planned, task.ID, true); err != nil {
			return nil, fmt.Errorf("complete semantic review contains %w", err)
		}
	}

	return planned, nil
}

func validateSemanticOutcomes(planned map[string]bool, outcomes []SemanticOutcome) error {
	for _, outcome := range outcomes {
		if !planned[outcome.TaskID] || outcome.Status != OutcomeCompleted {
			return errors.New("complete semantic review contains an invalid or unfinished outcome")
		}

		delete(planned, outcome.TaskID)
	}

	return validateNoPendingTasks(planned, "complete semantic review")
}

func runDigest(run Run) (string, error) {
	run.Digest = ""

	run.Targets = append([]TargetResult(nil), run.Targets...)
	for i := range run.Targets {
		run.Targets[i].Label = ""
		run.Targets[i].Analysis.Source = nil
		run.Targets[i].Analysis.Vulnerabilities.QueriedAt = ""
	}

	data, err := canonicalValue(nil, reflect.ValueOf(struct {
		Operation Operation `json:"operation"`
		Run       Run       `json:"run"`
	}{Operation: run.Operation, Run: run}), "")
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(data)

	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func unorderedCollection(field string) bool {
	switch field {
	case "findings", "observations", "diagnostics", "rules", "checks", "files", "skills", "objects", "skipped",
		"plugins", "components", "edges", "references", "issues", "requirements", "outcomes",
		"proposals", "assessments", "proposal_assessments", "queries", "matches", "aliases",
		"dependency_ids", "context_signals", "signature_names", "related_evidence", "contexts",
		"manifests", "declarations", "assets", "prompts", "link_ids", "finding_ids", "proposal_ids",
		"knowledge_topic_ids", "sources", "reasons", "problems", "suppressed":
		return true
	default:
		return false
	}
}
