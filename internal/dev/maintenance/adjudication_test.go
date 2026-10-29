//nolint:testpackage // Tests verify private adjudication admission and artifact bindings.
package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/report"
)

func TestAdjudicationRetainsStrictRuntimeAndInputRefusalContracts(t *testing.T) {
	record := validReplayRecord()
	if err := validAdjudicationResult(record); err != nil {
		t.Fatal(err)
	}
	record.State = report.RunFailed
	record.Coverage = report.Failed
	record.Error = "input byte limit"
	record.RunDigest = ""
	if err := validAdjudicationResult(record); err != nil {
		t.Fatal("documented input refusal lost")
	}
	record.Error = "analyzer panic"
	if err := validAdjudicationResult(record); err == nil {
		t.Fatal("runtime failure was accepted for adjudication")
	}
	record = validReplayRecord()
	record.RunDigest = ""
	if err := validAdjudicationResult(record); err == nil {
		t.Fatal("unbound current replay accepted")
	}
}

func TestAdjudicationReasonsSeparateScopeTaxonomyAndDetectionGaps(t *testing.T) {
	row := replayDifference{Function: "node", Input: "normal", Files: map[string]capturedBlob{"input.py": {}}}
	result := validReplayRecord()
	if reason := deltaReason(row, result, "missing", "AST1", false, "python"); reason != "resolved" {
		t.Fatal(reason)
	}
	refused := result
	refused.Error = "input byte limit"
	if reason := deltaReason(row, refused, "missing", "AST1", true, "python"); reason != "refused" {
		t.Fatal(reason)
	}
	component := row
	component.Function = "helper"
	if reason := deltaReason(component, result, "missing", "AST1", true, "python"); reason != "component" {
		t.Fatal(reason)
	}
	if reason := deltaReason(row, result, "extra", "AST1", true, "python"); reason != "python" {
		t.Fatal(reason)
	}
	gap := row
	gap.Input = "89270abdb8a5d12c004cc1ee1af6045a4505ccf5aaf005ef402c8d98f791a5aa"
	if reason := deltaReason(gap, result, "missing", "SC2", true, "supply"); reason != "known_gap" {
		t.Fatal(reason)
	}
	counterpart := result
	counterpart.Findings = []report.Finding{{RuleID: "PY-TT5", Location: report.Location{Path: "input.py"}}}
	if reason := deltaReason(row, counterpart, "missing", "TT1", true, "python"); reason != "taxonomy" {
		t.Fatal(reason)
	}
	contextRow := row
	contextRow.Files = map[string]capturedBlob{"README.md": {}}
	contextRow.ContextFlags = []string{"file_type:python"}
	if reason := deltaReason(contextRow, result, "missing", "AST1", true, "python"); reason != "type_context" {
		t.Fatal(reason)
	}
	if !hasPythonFilename(map[string]capturedBlob{"types.PYI": {}}) || hasPythonFilename(contextRow.Files) {
		t.Fatal("filename/type context merged")
	}
}

func TestSavedAdjudicationBindsSitesInputsResultsAndRuntimeFiles(t *testing.T) {
	root, upstream := t.TempDir(), t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	files := map[string]string{
		"go.mod": "module example.invalid/scout\n\ngo 1.26.0\n", "go.sum": "",
		"scan.go":                            "package scout\nimport _ \"example.invalid/scout/internal/analysis/engine\"\n",
		"internal/analysis/engine/engine.go": "package engine\n",
		"cmd/scout/main.go":                  "package main\nimport _ \"example.invalid/scout\"\nfunc main(){}\n",
	}
	for name, data := range files {
		maintenanceFile(t, root, name, []byte(data))
	}
	testName := "tests/test_example.py::test_case"
	testData := []byte("def test_case():\n    pass\n")
	maintenanceFile(t, upstream, "tests/test_example.py", testData)
	maintenanceJSON(t, root, "testdata/provenance/upstream-adjudication-0.22.json", object{"test_sites": []testSite{{
		Test:   testName,
		File:   "tests/test_example.py",
		Line:   1,
		SHA256: digest(testData),
	}}})
	record := validReplayRecord()
	row := replayDifference{
		Observation: "observation",
		Test:        testName,
		Input:       record.ID,
		Function:    "node",
		Missing:     []string{"AST1"},
		Files:       map[string]capturedBlob{"input.py": {}},
	}
	before := suiteComparison{ScannedInputs: 1, Differences: []replayDifference{row}}
	after := suiteComparison{ScannedInputs: 1, Differences: []replayDifference{row}}
	previous := maintenanceJSON(t, root, "before.json", before)
	current := maintenanceJSON(t, root, "after.json", after)
	data, _ := json.Marshal(record)
	results := maintenanceFile(t, root, "results.jsonl", append(data, '\n'))
	output := filepath.Join(root, "adjudication.json")
	o := options{
		root: root,
		values: map[string]*string{
			"before":   &previous,
			"after":    &current,
			"results":  &results,
			"upstream": &upstream,
			"output":   &output,
		},
	}
	a, _, err := newAdjudicator(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.addAllObservations(t.Context()); err != nil || len(a.rows) != 1 || len(a.sites) != 1 || len(a.inputs) != 1 {
		t.Fatalf("saved observation binding failed: %+v %v", a, err)
	}
	if err := a.addObservation(t.Context(), row.Observation); err != nil || len(a.sites) != 1 {
		t.Fatal("parametrized observation lost site reuse")
	}
	var summary bytes.Buffer
	if err := adjudicateUpstreamSuite(t.Context(), o, &summary); err != nil {
		t.Fatal(err)
	}
	var document object
	if err := readJSON(output, &document); err != nil || len(array(document["rows"])) != 1 || len(array(document["runtime_files"])) < 3 {
		t.Fatal("adjudication lost its evidence bindings")
	}
	if _, err := indexAdjudicationDifferences([]replayDifference{row, row}, "current"); err == nil {
		t.Fatal("duplicate observation accepted")
	}
	if err := a.addResult(record); err == nil {
		t.Fatal("duplicate replay result accepted")
	}

	blank := row
	blank.Missing = nil
	blank.Extra = nil
	a.old[row.Observation] = blank
	a.current[row.Observation] = blank
	refused := record
	refused.Error = "input byte limit"
	refused.State = report.RunFailed
	refused.Coverage = report.Failed
	refused.Diagnostics = nil
	a.results[record.ID] = refused
	if err := a.addObservation(t.Context(), row.Observation); err != nil || a.counts["refused"] != 1 || a.rows[len(a.rows)-1][14] != "input byte limit" {
		t.Fatal("refused observation lost its reason or error evidence")
	}
	a.results[record.ID] = record
	delete(a.current, row.Observation)
	if err := a.addObservation(t.Context(), row.Observation); err != nil || a.counts["resolved"] != 1 {
		t.Fatal("resolved previous-only observation lost its disposition")
	}
	delete(a.results, record.ID)
	if err := a.addObservation(t.Context(), row.Observation); err == nil {
		t.Fatal("observation without a replay binding accepted")
	}
	a.results[record.ID] = record
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.addAllObservations(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled adjudication continued")
	}
}

func TestDefinitionTraversalPreservesLexicalScope(t *testing.T) {
	method, _ := frontend.NewNode(frontend.FunctionDef, 2, 3, frontend.TextField(frontend.FieldName, "test_case"))
	class, _ := frontend.NewNode(frontend.ClassDef, 0, 4, frontend.TextField(frontend.FieldName, "Example"), frontend.NodesField(frontend.Body, []*frontend.Node{method}))
	starts := make([]int, 0)
	findPythonDefinition(class, nil, []string{"Example", "test_case"}, &starts)
	if len(starts) != 1 || starts[0] != 2 {
		t.Fatal("lexical definition evidence changed")
	}
	if err := adjudicateUpstreamSuite(t.Context(), options{}, io.Discard); err == nil {
		t.Fatal("maintenance command accepted implicit input paths")
	}
}

func validReplayRecord() replayResult {
	return replayResult{
		ID:            strings.Repeat("a", 64),
		Version:       scout.Version(),
		BudgetSeconds: 30,
		State:         report.RunComplete,
		Coverage:      report.Complete,
		Decision:      report.Review,
		RunDigest:     "sha256:" + strings.Repeat("b", 64),
		Findings:      []report.Finding{},
		Diagnostics:   []string{},
	}
}
