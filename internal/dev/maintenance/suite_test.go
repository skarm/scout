//nolint:testpackage // Exercises private implementation details and package fixtures.
package maintenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func TestPrepareSuiteRefusesBrokenCaptureAndExistingOutput(t *testing.T) {
	capture := t.TempDir()
	if err := prepareSuite(t.Context(), capture, filepath.Join(t.TempDir(), "new"), io.Discard); err == nil {
		t.Fatal("missing capture summary accepted")
	}
	for _, summary := range []object{{"exit_status": 1}, {"capture_errors": []any{"incomplete"}}} {
		maintenanceJSON(t, capture, "capture-summary.json", summary)
		if err := prepareSuite(t.Context(), capture, filepath.Join(t.TempDir(), "new"), io.Discard); err == nil {
			t.Fatal("failed capture accepted")
		}
	}
	maintenanceJSON(t, capture, "capture-summary.json", object{"exit_status": 0, "capture_errors": []any{}})
	if err := prepareSuite(t.Context(), capture, t.TempDir(), io.Discard); err == nil {
		t.Fatal("existing replay output accepted")
	}
	maintenanceFile(t, capture, "observations.jsonl", []byte(`{"id":""}`+"\n"))
	if err := prepareSuite(t.Context(), capture, filepath.Join(t.TempDir(), "new"), io.Discard); err == nil {
		t.Fatal("capture observation missing its identity accepted")
	}
}

func TestStaticKnowledgeExpectationsRespectAvailabilityAndGuidance(t *testing.T) {
	report := func() object {
		return object{
			"semantic":  object{"enabled": false},
			findingsKey: []any{object{"rule_id": "R1"}},
			"inspection": object{"checks": []any{object{
				"id":        "python",
				"available": true,
			}}},
			"rules": []any{object{
				"id":       "R1",
				"guidance": object{"sources": []any{object{"symbol": "topic"}}},
			}},
		}
	}
	tc := knowledgeCase{Topic: "topic", StaticExpected: "R1", RequiresPython: true}
	if found, applicable, err := checkStaticKnowledge(report(), tc); err != nil || !applicable || len(found) != 1 {
		t.Fatal("available static control rejected")
	}
	unavailable := report()
	unavailable["inspection"] = object{"checks": []any{object{"id": "python", "available": false}}}
	unavailable[findingsKey] = []any{}
	if _, applicable, err := checkStaticKnowledge(unavailable, tc); err != nil || applicable {
		t.Fatal("unavailable parser acquired a static expectation")
	}
	for _, mutate := range []func(object){func(r object) { r["semantic"] = object{"enabled": true} }, func(r object) { r[findingsKey] = []any{} }, func(r object) { r["rules"] = []any{} }} {
		value := report()
		mutate(value)
		if _, _, err := checkStaticKnowledge(value, tc); err == nil {
			t.Fatal("invalid static control/guidance accepted")
		}
	}
	forbidden := tc
	forbidden.StaticForbidden = "R1"
	if _, _, err := checkStaticKnowledge(report(), forbidden); err == nil {
		t.Fatal("forbidden static control accepted")
	}
}

func TestMissingSavedInputsFailBeforePreparingOutputOrAdjudicationState(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(t.TempDir(), "not-created")
	if _, err := prepareComparison(root, output, t.TempDir(), sourceInventory{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing corpus did not retain its input error: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing corpus materialized output")
	}
	missing := filepath.Join(root, "missing-comparison.json")
	a, _, err := newAdjudicator(t.Context(), options{root: root, values: map[string]*string{"before": &missing}})
	if !errors.Is(err, os.ErrNotExist) || a != nil {
		t.Fatal("missing saved comparison created adjudication state")
	}
}

func TestPrepareRequiresTypedCompleteCaptureSummary(t *testing.T) {
	for _, summary := range []string{
		`{}`, `null`,
		`{"exit_status":"failed","capture_errors":"broken"}`,
		`{"exit_status":0,"capture_errors":null}`,
		`{"exit_status":0,"capture_errors":{}}`,
		`{"exit_status":0.5,"capture_errors":[]}`,
		`{"exit_status":0,"capture_errors":[],"exit_status":1}`,
		`{"exit_status":0,"capture_errors":["failed"]}`,
	} {
		t.Run(summary, func(t *testing.T) {
			capture := t.TempDir()
			maintenanceFile(t, capture, "capture-summary.json", []byte(summary))
			maintenanceFile(t, capture, "collection.json", []byte(`{"Tests":[]}`))
			maintenanceFile(t, capture, "observations.jsonl", nil)
			maintenanceFile(t, capture, "test-status.jsonl", nil)
			output := filepath.Join(t.TempDir(), "prepared")
			var out bytes.Buffer
			if err := prepareSuite(context.Background(), capture, output, &out); err == nil {
				t.Fatalf("invalid capture admitted: %s", out.String())
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid capture created output", err)
			}
		})
	}
}

func TestCaptureSummaryPreservesValidDataAndBoundsAdmission(t *testing.T) {
	for _, exit := range []string{"0", "-0"} {
		data := `{"exit_status":` + exit + `,"capture_errors":[],"extra":"preserved"}`
		path := filepath.Join(t.TempDir(), "capture-summary.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readCaptureSummary(context.Background(), path)
		if err != nil || string(got) != data {
			t.Fatalf("summary changed during admission: %s %v", got, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := readCaptureSummary(ctx, path); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled admission: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "oversized.json")
	data := `{"exit_status":0,"capture_errors":[],"extra":"` + strings.Repeat("x", jsonconfig.MaxBytes) + `"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCaptureSummary(context.Background(), path); err == nil {
		t.Fatal("unbounded capture summary admitted")
	}
	const base = `{"exit_status":0,"capture_errors":[]}`
	for _, size := range []int{jsonconfig.MaxBytes, jsonconfig.MaxBytes + 1} {
		data := base + strings.Repeat(" ", size-len(base))
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readCaptureSummary(context.Background(), path)
		if (err == nil) != (size == jsonconfig.MaxBytes) {
			t.Fatalf("summary byte boundary %d: %v", size, err)
		}
	}
	if _, err := readCaptureSummary(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing capture summary admitted")
	}
}
