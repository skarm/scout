package maintenance

import "testing"

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
