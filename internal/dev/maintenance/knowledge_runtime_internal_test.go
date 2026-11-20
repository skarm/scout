package maintenance

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCLIOutputEnforcesByteLimit(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantBytes   int64
		wantError   error
	}{
		{name: "exact limit", input: "text", wantBytes: 4},
		{name: "over the limit", input: "texts", wantError: errKnowledgeOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &cliOutput{limit: 4}
			n, err := io.Copy(output, io.LimitReader(strings.NewReader(tc.input), int64(len(tc.input))))
			if !errors.Is(err, tc.wantError) || n != tc.wantBytes || int64(output.data.Len()) != tc.wantBytes || output.overflow != (tc.wantError != nil) {
				t.Fatalf("copied %d bytes, retained %d bytes, overflow=%t, error=%v", n, output.data.Len(), output.overflow, err)
			}
		})
	}
}

func TestKnowledgeCasesHonorCancellationBeforeListening(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rows, err := runKnowledgeCases(ctx, options{}, "", &fixtureReviewer{}, nil); rows != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fixture startup returned rows=%v, err=%v", rows, err)
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
