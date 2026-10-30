// Package validation accounts for a fixed post-discovery plan. It does not run
// checks or infer missing results. An absent/duplicate/unknown result is an error.
package validation

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

const MaxTasks = 131072

// Ledger is mutated only by the engine coordinator. Workers read fixed scheduling
// decisions. Tasks and inputs are copied before execution and bound to bytes.
type Ledger struct {
	tasks     []report.AnalysisTask
	index     map[string]int
	analyzers map[string]int
	files     []report.File
	fileIndex map[string]int
	results   map[string]report.TaskOutcome
	issues    map[string]bool
	omitted   int
	max       int
	digest    string
}

func New(files []report.File, rules []report.Rule, g report.ComponentGraph) *Ledger {
	return NewWithLimit(files, rules, g, MaxTasks)
}

// NewWithSemantic creates a ledger with optional semantic analysis and a bounded task limit.
func NewWithSemantic(files []report.File, rules []report.Rule, g report.ComponentGraph, enabled bool) *Ledger {
	return newLedger(files, rules, g, MaxTasks, enabled)
}

func NewWithLimit(files []report.File, rules []report.Rule, g report.ComponentGraph, limit int) *Ledger {
	return newLedger(files, rules, g, limit, false)
}

func newLedger(files []report.File, rules []report.Rule, g report.ComponentGraph, limit int, semanticEnabled bool) *Ledger {
	if limit < 1 {
		limit = 1
	}

	if limit > MaxTasks {
		limit = MaxTasks
	}

	l := &Ledger{
		tasks: []report.AnalysisTask{}, index: map[string]int{}, analyzers: map[string]int{},
		fileIndex: map[string]int{}, results: map[string]report.TaskOutcome{}, issues: map[string]bool{}, max: limit,
	}
	// Discovery-dependent obligations are explicit; unsupported is not success.
	// Phase order is part of the bounded plan and its stable hash.
	l.planLoaders(g.Plugins)
	l.planReferences(g.References)
	l.planDiscoveryGaps(g.Issues)
	l.planSemantic(semanticEnabled)
	l.planAnalyzers(files, rules)
	l.bindPlan(g.RequestedHost)

	return l
}

func (l *Ledger) Scheduled(rule, file string) bool {
	_, analyzer := l.analyzers[rule]
	_, input := l.fileIndex[file]

	return analyzer && input
}

// Record reports a terminal outcome for a known task. No result can rewrite an
// earlier one. The first outcome is retained and the duplicate is a contract gap.
func (l *Ledger) Record(id, status, reason string) { l.record(id, status, reason) }

// CompleteAnalyzer closes one analyzer's inventory-bound task only after every
// planned input has exactly one valid outcome. Per-file details remain in coverage.
func (l *Ledger) CompleteAnalyzer(rule string, files []report.File, checks []report.FileCheck) {
	index, planned := l.analyzers[rule]
	if !planned {
		return
	}

	status := report.OutcomeNotApplicable

	if len(files) != len(l.files) || len(files) != len(checks) {
		l.issues["task_result_count_mismatch"] = true
		status = report.OutcomePartial
	}

	seen := make([]bool, len(l.files))
	for i, c := range checks {
		if i >= len(files) {
			break
		}

		input, known := l.fileIndex[files[i].Path]
		if !known || seen[input] || l.files[input] != files[i] {
			l.issues["task_input_mismatch"] = true
			status = report.OutcomePartial
		} else {
			seen[input] = true
		}

		if c.AnalyzerID != rule {
			l.issues["task_analyzer_mismatch"] = true
			status = report.OutcomePartial
		}

		terminal := l.normalizeStatus(c.Status)
		if terminal != report.OutcomeCompleted && terminal != report.OutcomeNotApplicable {
			status = report.OutcomePartial
		} else if terminal == report.OutcomeCompleted && status == report.OutcomeNotApplicable {
			status = report.OutcomeCompleted
		}
	}

	l.record(l.tasks[index].ID, status, "file_outcomes_"+status)
}

func (l *Ledger) Tasks() []report.AnalysisTask { return append([]report.AnalysisTask(nil), l.tasks...) }

func (l *Ledger) Finalize() report.ValidationReport {
	r := report.ValidationReport{
		Scope:        "post-discovery-static-plan plus optional semantic parent; semantic child plan and capture/extraction/preparation reported separately",
		PlanSHA256:   l.digest,
		MaxTasks:     l.max,
		OmittedTasks: l.omitted,
		Tasks:        l.Tasks(),
		Outcomes:     []report.TaskOutcome{},
		Completeness: report.Complete,
		Issues:       []string{},
	}
	for _, t := range l.tasks {
		o, ok := l.results[t.ID]
		if !ok {
			o = report.TaskOutcome{TaskID: t.ID, Status: report.OutcomeMissing, Reason: "planned_task_has_no_result"}
			r.Completeness = report.Partial
		}

		if t.Required && o.Status != report.OutcomeCompleted && o.Status != report.OutcomeNotApplicable {
			r.Completeness = report.Partial
		}

		r.Outcomes = append(r.Outcomes, o)
	}

	if l.omitted > 0 {
		r.Issues = append(r.Issues, "task_budget_exceeded:"+strconv.Itoa(l.omitted))
		r.Completeness = report.Partial
	}

	for issue := range l.issues {
		r.Issues = append(r.Issues, issue)
		r.Completeness = report.Partial
	}

	sort.Strings(r.Issues)

	return r
}

// CompleteSemantic closes the pre-scheduled parent task. Its bounded child plan
// and evidence scopes are reported separately under semantic, before any calls.
func (l *Ledger) CompleteSemantic(completeness report.Completeness) {
	status := report.OutcomeCompleted
	if completeness != report.Complete {
		status = report.OutcomePartial
	}

	if completeness == report.Failed {
		status = report.OutcomeFailed
	}

	for _, t := range l.tasks {
		if t.Kind == "semantic_review" && t.Required {
			l.record(t.ID, status, "semantic_child_plan_"+status)
		}
	}
}

func (l *Ledger) planLoaders(plugins []report.PluginInterpretation) {
	for _, p := range plugins {
		t := report.AnalysisTask{Kind: "loader_contract", PluginID: p.ID, Version: p.AdapterVersion, Required: true}

		id := l.add(t)
		if id != "" {
			l.record(id, report.OutcomeUnsupported, "full_runtime_loader_contract_not_verified")
		}
	}
}

func (l *Ledger) planReferences(references []report.ComponentReference) {
	for _, ref := range references {
		t := report.AnalysisTask{
			Kind:        "reference_resolution",
			PluginID:    ref.PluginID,
			ComponentID: ref.ComponentID,
			ReferenceID: ref.ID,
			Version:     "1",
			Required:    true,
		}
		if ref.Source != nil {
			t.Path = ref.Source.Path
			t.InputSHA256 = ref.Source.SHA256
		}

		id := l.add(t)
		if id != "" {
			if ref.Status == "resolved" {
				l.record(id, report.OutcomeCompleted, "captured_reference_only")
			} else {
				l.record(id, report.OutcomeUnsupported, "reference_or_dependency_unresolved")
			}
		}
	}
}

func (l *Ledger) planDiscoveryGaps(issues []report.HarnessIssue) {
	for _, issue := range issues {
		t := report.AnalysisTask{
			Kind:       "discovery_gap",
			AnalyzerID: issue.Code,
			Version:    "1",
			Path:       issue.Path,
			PluginID:   issue.PluginID,
			Required:   true,
		}

		id := l.add(t)
		if id != "" {
			status := report.OutcomeUnsupported
			if issue.Status == "invalid" {
				status = report.OutcomeFailed
			}

			l.record(id, status, "discovery_reported_"+issue.Status)
		}
	}
}

func (l *Ledger) planSemantic(enabled bool) {
	// Explicit non-selection is not silently downgraded from a requested mode.
	id := l.add(report.AnalysisTask{Kind: "semantic_review", Version: "1", Required: enabled})
	if id != "" && !enabled {
		l.record(id, report.OutcomeDisabled, "semantic_review_not_requested")
	}
}

func (l *Ledger) planAnalyzers(files []report.File, rules []report.Rule) {
	l.files = append([]report.File(nil), files...)
	rs := append([]report.Rule(nil), rules...)

	sort.Slice(l.files, func(i, j int) bool { return l.files[i].Path < l.files[j].Path })
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })

	for i, file := range l.files {
		if _, duplicate := l.fileIndex[file.Path]; duplicate {
			l.issues["duplicate_planned_task"] = true
		}

		l.fileIndex[file.Path] = i
	}
	// The same sorted inventory binds every analyzer. Store it once rather than
	// retaining a task and outcome for every file/rule pair.
	encoded, _ := json.Marshal(l.files)

	inputDigest := artifact.Hash(encoded)
	for _, r := range rs {
		l.add(report.AnalysisTask{
			Kind: "analyzer", AnalyzerID: r.ID, Version: r.Version,
			InputSHA256: inputDigest, Required: true,
		})
	}
}

func (l *Ledger) bindPlan(host string) {
	raw, _ := json.Marshal(struct {
		Version string
		Host    string
		Tasks   []report.AnalysisTask
	}{Version: "validation-plan-v3", Host: host, Tasks: l.tasks})
	l.digest = artifact.Hash(raw)
}

func (l *Ledger) add(t report.AnalysisTask) string {
	if len(l.tasks) >= l.max {
		l.omitted++
		return ""
	}

	raw, _ := json.Marshal(t)

	t.ID = artifact.Hash(raw)
	if _, ok := l.index[t.ID]; ok {
		l.issues["duplicate_planned_task"] = true
		return ""
	}

	if t.Kind == "analyzer" {
		if _, duplicate := l.analyzers[t.AnalyzerID]; duplicate {
			l.issues["duplicate_planned_task"] = true
			return ""
		}

		l.analyzers[t.AnalyzerID] = len(l.tasks)
	}

	l.index[t.ID] = len(l.tasks)

	l.tasks = append(l.tasks, t)

	return t.ID
}

func (l *Ledger) record(id, status, reason string) {
	if _, ok := l.index[id]; !ok {
		l.issues["unknown_task_result"] = true
		return
	}

	if _, ok := l.results[id]; ok {
		l.issues["duplicate_task_result"] = true
		return
	}

	if normalized := l.normalizeStatus(status); normalized != status {
		status, reason = normalized, "invalid_outcome"
	}
	// Reasons are scanner-controlled enums, not analyzer error strings.
	if len(reason) == 0 || len(reason) > 128 {
		l.issues["invalid_task_reason"] = true
		reason = "invalid_reason"
		status = report.OutcomeFailed
	}

	l.results[id] = report.TaskOutcome{TaskID: id, Status: status, Reason: reason}
}

func (l *Ledger) normalizeStatus(status string) string {
	switch status {
	case report.OutcomeCompleted, report.OutcomeNotApplicable, report.OutcomeUnsupported, report.OutcomeDisabled, report.OutcomeCancelled, report.OutcomeFailed, report.OutcomePartial, report.OutcomeNotRun:
		return status
	default:
		l.issues["invalid_task_outcome"] = true
		return report.OutcomeFailed
	}
}
