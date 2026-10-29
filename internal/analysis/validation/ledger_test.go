package validation_test

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/validation"
	"github.com/skarm/scout/report"
)

func TestPlanExistsBeforeExecutionAndIsDefensive(t *testing.T) {
	fs, rs := inputs()
	l := validation.New(fs, rs, report.ComponentGraph{})
	before := l.Tasks()
	if len(before) != 3 {
		t.Fatal(before)
	}
	before[0].Kind = "mutated"
	if l.Tasks()[0].Kind == "mutated" {
		t.Fatal("mutable plan")
	}
	if l.Finalize().Completeness != "partial" {
		t.Fatal("missing results treated as clean")
	}
	l.CompleteAnalyzer("R", fs, []report.FileCheck{{AnalyzerID: "R", Status: "completed"}, {
		AnalyzerID: "R",
		Status:     "not_applicable",
	}})
	r := l.Finalize()
	if r.Completeness != "complete" || len(r.Tasks) != len(r.Outcomes) {
		t.Fatalf("%+v", r)
	}
	if !l.Scheduled("R", "a") || l.Scheduled("R", "unknown") {
		t.Fatal("schedule mismatch")
	}
}

func TestLedgerFailures(t *testing.T) {
	for _, status := range []string{"failed", "partial", "not_run", "cancelled", "disabled", "unsupported", "made_up"} {
		t.Run(status, func(t *testing.T) {
			fs, rs := inputs()
			l := validation.New(fs, rs, report.ComponentGraph{})
			l.CompleteAnalyzer("R", fs, []report.FileCheck{{AnalyzerID: "R", Status: status}, {
				AnalyzerID: "R",
				Status:     "completed",
			}})
			if l.Finalize().Completeness != "partial" {
				t.Fatal("bad outcome allowed")
			}
		})
	}
}

func TestContractViolations(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*validation.Ledger, []report.File)
	}{
		{name: "unknown", run: func(l *validation.Ledger, _ []report.File) { l.Record("unknown", "completed", "ok") }},
		{
			name: "duplicate",
			run:  func(l *validation.Ledger, _ []report.File) { id := l.Tasks()[0].ID; l.Record(id, "completed", "ok") },
		},
		{name: "count", run: func(l *validation.Ledger, fs []report.File) { l.CompleteAnalyzer("R", fs, nil) }},
		{name: "analyzer", run: func(l *validation.Ledger, fs []report.File) {
			l.CompleteAnalyzer("R", fs, []report.FileCheck{{AnalyzerID: "X", Status: "completed"}, {
				AnalyzerID: "R",
				Status:     "completed",
			}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, rs := inputs()
			l := validation.New(fs, rs, report.ComponentGraph{})
			tc.run(l, fs)
			r := l.Finalize()
			if r.Completeness != "partial" || len(r.Issues) == 0 {
				t.Fatal("contract failure lost")
			}
		})
	}
}

func TestBudgetAndDigests(t *testing.T) {
	fs, rs := inputs()
	a := validation.NewWithLimit(fs, rs, report.ComponentGraph{}, 2)
	r := a.Finalize()
	if r.OmittedTasks != 1 || len(r.Tasks) != 2 || r.Completeness != "partial" || a.Scheduled("R", "b") {
		t.Fatal(r)
	}
	b := validation.New(fs, rs, report.ComponentGraph{}).Finalize()
	fs[0].SHA256 = "changed"
	c := validation.New(fs, rs, report.ComponentGraph{}).Finalize()
	if b.PlanSHA256 == c.PlanSHA256 {
		t.Fatal("plan not bound to bytes")
	}
	fs[0], fs[1] = fs[1], fs[0]
	d := validation.New(fs, rs, report.ComponentGraph{}).Finalize()
	if !reflect.DeepEqual(c, d) {
		t.Fatal("input order changed plan")
	}
}

func TestPluginAndDependencyObligations(t *testing.T) {
	g := report.ComponentGraph{
		Plugins: []report.PluginInterpretation{{ID: "plugin", AdapterVersion: "1"}},
		References: []report.ComponentReference{{
			ID:          "ref",
			ComponentID: "component",
			Status:      "unresolved",
		}},
	}
	r := validation.New(nil, nil, g).Finalize()
	if r.Completeness != "partial" || len(r.Tasks) != 3 || len(r.Outcomes) != 3 {
		t.Fatal(r)
	}
	for _, o := range r.Outcomes {
		if o.Status == "missing" {
			t.Fatal("known unsupported obligation lost")
		}
	}
}

func TestDuplicatePlanAndInvalidReason(t *testing.T) {
	fs, rs := inputs()
	fs = append(fs, fs[0])
	l := validation.New(fs, rs, report.ComponentGraph{})
	if len(l.Finalize().Issues) == 0 {
		t.Fatal("duplicate task hidden")
	}
	l = validation.New(fs[:1], rs, report.ComponentGraph{})
	for _, task := range l.Tasks() {
		if task.Kind == "analyzer" {
			l.Record(task.ID, "completed", "")
		}
	}
	if l.Finalize().Completeness != "partial" {
		t.Fatal("invalid reason accepted")
	}
}

func TestDiscoveryIssuesAndHostArePartOfValidation(t *testing.T) {
	g := report.ComponentGraph{
		RequestedHost: "auto",
		Issues: []report.HarnessIssue{{
			Code:   "marketplace_install_closure_unverified",
			Status: "partial",
		}},
	}
	a := validation.New(nil, nil, g).Finalize()
	if a.Completeness != "partial" {
		t.Fatal("discovery gap lost")
	}
	g.RequestedHost = "codex"
	b := validation.New(nil, nil, g).Finalize()
	if a.PlanSHA256 == b.PlanSHA256 {
		t.Fatal("requested host absent from plan binding")
	}
	g.Plugins = []report.PluginInterpretation{{ID: "p", AdapterVersion: "1"}}
	for _, task := range validation.New(nil, nil, g).Tasks() {
		if task.Kind == "loader_contract" && (task.PluginID != "p" || task.ComponentID != "") {
			t.Fatal("plugin ID mislabelled as component ID")
		}
	}
}

func TestAnalyzerCompletionPreservesPlanAndOutcomeOrder(t *testing.T) {
	files, rules := multiInputs()
	first := validation.New(files, rules, report.ComponentGraph{RequestedHost: "auto"})
	plan := first.Finalize()
	for _, rule := range []string{"B", "A"} {
		first.CompleteAnalyzer(rule, files, orderedChecks(rule, files))
	}
	a := first.Finalize()
	if a.Completeness != report.Complete || a.PlanSHA256 != plan.PlanSHA256 || !reflect.DeepEqual(a.Tasks, plan.Tasks) {
		t.Fatalf("execution changed plan or failed completion: %+v", a)
	}
	if got := taskOrder(a.Tasks); !slices.Equal(got, []string{"semantic_review", "A:a", "B:a", "A:b", "B:b"}) {
		t.Fatalf("task order changed: %v", got)
	}
	for i, outcome := range a.Outcomes {
		want := "completed"
		if a.Tasks[i].AnalyzerID == "A" && a.Tasks[i].Path == "b" {
			want = "not_applicable"
		}
		if outcome.TaskID != a.Tasks[i].ID || (a.Tasks[i].Kind == "analyzer" && outcome.Status != want) {
			t.Fatalf("outcome detached from planned task at %d: %+v", i, outcome)
		}
	}

	slices.Reverse(files)
	slices.Reverse(rules)
	second := validation.New(files, rules, report.ComponentGraph{RequestedHost: "auto"})
	for _, rule := range []string{"A", "B"} {
		second.CompleteAnalyzer(rule, files, orderedChecks(rule, files))
	}
	if b := second.Finalize(); !reflect.DeepEqual(a, b) {
		t.Fatalf("input or completion order changed result:\nfirst: %+v\nsecond: %+v", a, b)
	}
}

func TestAnalyzerCompletionRetainsMissingAndFirstDuplicateOutcome(t *testing.T) {
	files, rules := multiInputs()
	l := validation.New(files, rules, report.ComponentGraph{})
	l.CompleteAnalyzer("A", files, completedChecks("A", len(files)))
	l.CompleteAnalyzer("A", files, []report.FileCheck{{AnalyzerID: "A", Status: "failed"}, {
		AnalyzerID: "A",
		Status:     "failed",
	}})
	r := l.Finalize()
	if r.Completeness != report.Partial || !slices.Equal(r.Issues, []string{"duplicate_task_result"}) {
		t.Fatalf("duplicate outcome contract lost: %+v", r)
	}
	for i, task := range r.Tasks {
		switch task.AnalyzerID {
		case "A":
			if r.Outcomes[i].Status != "completed" {
				t.Fatalf("duplicate rewrote original outcome: %+v", r.Outcomes[i])
			}
		case "B":
			if r.Outcomes[i].Status != "missing" || r.Outcomes[i].Reason != "planned_task_has_no_result" {
				t.Fatalf("another analyzer was implicitly completed: %+v", r.Outcomes[i])
			}
		}
	}
}

func TestAnalyzerCompletionOnlyCompletesRetainedTasks(t *testing.T) {
	files, rules := multiInputs()
	for _, limit := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprintf("limit-%d", limit), func(t *testing.T) {
			l := validation.NewWithLimit(files, rules, report.ComponentGraph{}, limit)
			plan := l.Finalize()
			for _, rule := range rules {
				l.CompleteAnalyzer(rule.ID, files, completedChecks(rule.ID, len(files)))
			}
			r := l.Finalize()
			if !reflect.DeepEqual(r.Tasks, plan.Tasks) || r.PlanSHA256 != plan.PlanSHA256 || r.OmittedTasks != 5-limit {
				t.Fatalf("completion changed capped plan: %+v", r)
			}
			for i, task := range r.Tasks {
				if task.Kind == "analyzer" && (r.Outcomes[i].Status != "completed" || !l.Scheduled(task.AnalyzerID, task.Path)) {
					t.Fatalf("retained task not completed: %+v", task)
				}
			}
			if limit < 5 && (r.Completeness != report.Partial || !slices.Contains(r.Issues, fmt.Sprintf("task_budget_exceeded:%d", 5-limit))) {
				t.Fatalf("omitted work was presented as complete: %+v", r)
			}
		})
	}
}

func TestAnalyzerCompletionDoesNotCompleteDiscoveryWithSameID(t *testing.T) {
	files, rules := inputs()
	g := report.ComponentGraph{Issues: []report.HarnessIssue{{Code: "R", Path: "a", Status: "partial"}}}
	l := validation.New(files, rules, g)
	l.CompleteAnalyzer("R", files, completedChecks("R", len(files)))
	r := l.Finalize()
	if r.Completeness != report.Partial || len(r.Issues) != 0 {
		t.Fatalf("discovery was overwritten as an analyzer task: %+v", r)
	}
	for i, task := range r.Tasks {
		if task.Kind == "discovery_gap" && r.Outcomes[i].Status != "unsupported" {
			t.Fatalf("discovery outcome changed: %+v", r.Outcomes[i])
		}
	}
}

func TestAnalyzerCompletionRejectsInvalidPerFileOutcomes(t *testing.T) {
	files, rules := inputs()
	l := validation.New(files, rules, report.ComponentGraph{})
	l.CompleteAnalyzer("R", files, []report.FileCheck{{AnalyzerID: "wrong", Status: "completed"}, {
		AnalyzerID: "R",
		Status:     "unknown",
	}})
	r := l.Finalize()
	if r.Completeness != report.Partial || !slices.Equal(r.Issues, []string{"invalid_task_outcome", "task_analyzer_mismatch"}) {
		t.Fatalf("invalid outcomes were accepted: %+v", r)
	}
	for i, task := range r.Tasks {
		switch task.Path {
		case "a":
			if r.Outcomes[i].Status != "missing" {
				t.Fatalf("wrong analyzer completed task: %+v", r.Outcomes[i])
			}
		case "b":
			if r.Outcomes[i].Status != "failed" || r.Outcomes[i].Reason != "invalid_outcome" {
				t.Fatalf("invalid status not normalized to failure: %+v", r.Outcomes[i])
			}
		}
	}
}

func TestPlanningPhasesPreserveOrderOutcomesAndDigest(t *testing.T) {
	files, rules := multiInputs()
	graph := planningGraph()
	ledger := validation.NewWithSemantic(files, rules, graph, true)
	got := ledger.Finalize()
	want := []struct {
		kind, plugin, reference, analyzer, path, status, reason string
	}{
		{
			kind:      "loader_contract",
			plugin:    "second",
			reference: "",
			analyzer:  "",
			path:      "",
			status:    "unsupported",
			reason:    "full_runtime_loader_contract_not_verified",
		},
		{
			kind:      "loader_contract",
			plugin:    "first",
			reference: "",
			analyzer:  "",
			path:      "",
			status:    "unsupported",
			reason:    "full_runtime_loader_contract_not_verified",
		},
		{
			kind:      "reference_resolution",
			plugin:    "first",
			reference: "ref-z",
			analyzer:  "",
			path:      "a",
			status:    "completed",
			reason:    "captured_reference_only",
		},
		{
			kind:      "reference_resolution",
			plugin:    "second",
			reference: "ref-a",
			analyzer:  "",
			path:      "",
			status:    "unsupported",
			reason:    "reference_or_dependency_unresolved",
		},
		{
			kind:      "discovery_gap",
			plugin:    "first",
			reference: "",
			analyzer:  "issue-z",
			path:      "a",
			status:    "failed",
			reason:    "discovery_reported_invalid",
		},
		{
			kind:      "discovery_gap",
			plugin:    "second",
			reference: "",
			analyzer:  "issue-a",
			path:      "b",
			status:    "unsupported",
			reason:    "discovery_reported_partial",
		},
		{
			kind:      "semantic_review",
			plugin:    "",
			reference: "",
			analyzer:  "",
			path:      "",
			status:    "missing",
			reason:    "planned_task_has_no_result",
		},
		{
			kind:      "analyzer",
			plugin:    "",
			reference: "",
			analyzer:  "A",
			path:      "a",
			status:    "missing",
			reason:    "planned_task_has_no_result",
		},
		{
			kind:      "analyzer",
			plugin:    "",
			reference: "",
			analyzer:  "B",
			path:      "a",
			status:    "missing",
			reason:    "planned_task_has_no_result",
		},
		{
			kind:      "analyzer",
			plugin:    "",
			reference: "",
			analyzer:  "A",
			path:      "b",
			status:    "missing",
			reason:    "planned_task_has_no_result",
		},
		{
			kind:      "analyzer",
			plugin:    "",
			reference: "",
			analyzer:  "B",
			path:      "b",
			status:    "missing",
			reason:    "planned_task_has_no_result",
		},
	}
	if len(got.Tasks) != len(want) || len(got.Outcomes) != len(want) || got.OmittedTasks != 0 || got.MaxTasks != validation.MaxTasks {
		t.Fatalf("plan accounting changed: tasks=%d outcomes=%d omitted=%d cap=%d", len(got.Tasks), len(got.Outcomes), got.OmittedTasks, got.MaxTasks)
	}
	for i, expected := range want {
		task, outcome := got.Tasks[i], got.Outcomes[i]
		if task.Kind != expected.kind || task.PluginID != expected.plugin || task.ReferenceID != expected.reference || task.AnalyzerID != expected.analyzer || task.Path != expected.path || !task.Required || outcome.TaskID != task.ID || outcome.Status != expected.status || outcome.Reason != expected.reason {
			t.Fatalf("task %d lost phase order or exact outcome: task=%+v outcome=%+v", i, task, outcome)
		}
	}
	const beforeRefactorDigest = "ee9f7954eb8ddd3e8c2cb94914449cd6b0d349f0336db87e8316a07c2658ad73"
	if got.PlanSHA256 != beforeRefactorDigest {
		t.Fatalf("exact plan binding changed: %s", got.PlanSHA256)
	}
	if files[0].Path != "b" || rules[0].ID != "B" || graph.Plugins[0].ID != "second" || graph.References[0].ID != "ref-z" {
		t.Fatal("planning reordered caller-owned input")
	}
	before := got.PlanSHA256
	ledger.CompleteSemantic(report.Complete)
	for _, rule := range rules {
		ledger.CompleteAnalyzer(rule.ID, files, completedChecks(rule.ID, len(files)))
	}
	if final := ledger.Finalize(); final.PlanSHA256 != before || final.Completeness != report.Partial || final.Outcomes[6].Status != "completed" {
		t.Fatal("execution changed the plan or hid unsupported discovery obligations")
	}
}

func TestPlanningCapsRetainDuplicateAndOmissionSemantics(t *testing.T) {
	files := []report.File{{Path: "a", SHA256: "digest-a"}}
	rules := []report.Rule{{ID: "R", Version: "1"}}
	graph := report.ComponentGraph{Plugins: []report.PluginInterpretation{{ID: "p", AdapterVersion: "1"}, {
		ID:             "p",
		AdapterVersion: "1",
	}}}
	for _, tc := range []struct {
		limit, retained, omitted int
		duplicate, scheduled     bool
	}{{limit: -1, retained: 1, omitted: 3, duplicate: false, scheduled: false}, {
		limit:     0,
		retained:  1,
		omitted:   3,
		duplicate: false,
		scheduled: false,
	}, {
		limit:     1,
		retained:  1,
		omitted:   3,
		duplicate: false,
		scheduled: false,
	}, {
		limit:     2,
		retained:  2,
		omitted:   1,
		duplicate: true,
		scheduled: false,
	}, {
		limit:     3,
		retained:  3,
		omitted:   0,
		duplicate: true,
		scheduled: true,
	}, {
		limit:     validation.MaxTasks + 1,
		retained:  3,
		omitted:   0,
		duplicate: true,
		scheduled: true,
	}} {
		t.Run(fmt.Sprintf("cap-%d", tc.limit), func(t *testing.T) {
			ledger := validation.NewWithLimit(files, rules, graph, tc.limit)
			plan := ledger.Finalize()
			ledger.CompleteAnalyzer("R", files, completedChecks("R", 1))
			got := ledger.Finalize()
			if len(got.Tasks) != tc.retained || got.OmittedTasks != tc.omitted || ledger.Scheduled("R", "a") != tc.scheduled || slices.Contains(got.Issues, "duplicate_planned_task") != tc.duplicate || got.PlanSHA256 != plan.PlanSHA256 || !reflect.DeepEqual(got.Tasks, plan.Tasks) {
				t.Fatalf("cap changed retained work, duplicates or binding: %+v", got)
			}
			if tc.omitted != 0 && !slices.Contains(got.Issues, fmt.Sprintf("task_budget_exceeded:%d", tc.omitted)) {
				t.Fatal("omitted planned work was not reported")
			}
			if got.MaxTasks != min(max(tc.limit, 1), validation.MaxTasks) || got.Completeness != report.Partial || got.Outcomes[0].Status != "unsupported" {
				t.Fatal("cap normalization or known unsupported loader outcome changed")
			}
		})
	}
}

func BenchmarkCompleteAnalyzers(b *testing.B) {
	files := make([]report.File, 128)
	for i := range files {
		files[i] = report.File{Path: fmt.Sprintf("file-%03d", i), SHA256: fmt.Sprintf("digest-%03d", i)}
	}
	for _, count := range []int{32, 64, 128, 256} {
		b.Run(fmt.Sprintf("rules-%d", count), func(b *testing.B) {
			rules := make([]report.Rule, count)
			checks := make([][]report.FileCheck, count)
			for i := range rules {
				rules[i] = report.Rule{ID: fmt.Sprintf("R%03d", i), Version: "1"}
				checks[i] = completedChecks(rules[i].ID, len(files))
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				l := validation.New(files, rules, report.ComponentGraph{})
				b.StartTimer()
				for j, rule := range rules {
					l.CompleteAnalyzer(rule.ID, files, checks[j])
				}
				b.StopTimer()
				if r := l.Finalize(); r.Completeness != report.Complete {
					b.Fatal("incomplete benchmark execution")
				}
			}
		})
	}
}

func planningGraph() report.ComponentGraph {
	return report.ComponentGraph{
		RequestedHost: "claude-code",
		Plugins: []report.PluginInterpretation{{ID: "second", AdapterVersion: "2"}, {
			ID:             "first",
			AdapterVersion: "1",
		}},
		References: []report.ComponentReference{
			{
				ID:          "ref-z",
				PluginID:    "first",
				ComponentID: "component-a",
				Status:      "resolved",
				Source: &report.SourceRef{
					Path:   "a",
					SHA256: "digest-a",
				},
			},
			{ID: "ref-a", PluginID: "second", ComponentID: "component-b", Status: "unresolved"},
		},
		Issues: []report.HarnessIssue{{Code: "issue-z", Path: "a", PluginID: "first", Status: "invalid"}, {
			Code:     "issue-a",
			Path:     "b",
			PluginID: "second",
			Status:   "partial",
		}},
	}
}

func multiInputs() ([]report.File, []report.Rule) {
	return []report.File{{Path: "b", SHA256: "digest-b"}, {Path: "a", SHA256: "digest-a"}}, []report.Rule{{
		ID:      "B",
		Version: "2",
	}, {
		ID:      "A",
		Version: "1",
	}}
}

func completedChecks(rule string, count int) []report.FileCheck {
	checks := make([]report.FileCheck, count)
	for i := range checks {
		checks[i] = report.FileCheck{AnalyzerID: rule, Status: "completed"}
	}
	return checks
}

func orderedChecks(rule string, files []report.File) []report.FileCheck {
	checks := completedChecks(rule, len(files))
	for i, file := range files {
		if rule == "A" && file.Path == "b" {
			checks[i].Status = "not_applicable"
		}
	}
	return checks
}

func taskOrder(tasks []report.AnalysisTask) []string {
	order := make([]string, len(tasks))
	for i, task := range tasks {
		order[i] = task.Kind
		if task.Kind == "analyzer" {
			order[i] = task.AnalyzerID + ":" + task.Path
		}
	}
	return order
}

func inputs() ([]report.File, []report.Rule) {
	return []report.File{{Path: "a", SHA256: "digest-a"}, {Path: "b", SHA256: "digest-b"}}, []report.Rule{{
		ID:      "R",
		Version: "1",
	}}
}
