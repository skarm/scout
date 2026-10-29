package semantic_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/review"
)

func TestAllCompiledKnowledgeRisksCanRoundTripOnlyInDiscovery(t *testing.T) {
	for _, topic := range knowledge.ReviewTopics() {
		for _, mode := range []string{"discovery", "intent", "tool_consistency", "quality"} {
			t.Run(topic.ID+"/"+mode, func(t *testing.T) {
				req := requestFixture()
				req.Mode = mode
				reply := responseFixture(req)
				p := proposal()
				p.Reason = "knowledge:" + topic.ID
				reply.Proposals = []review.Proposal{p}
				_, code := semantic.ValidateResponse(context.Background(), req, encoded(t, reply), 65536)
				if (code == "") != (mode == "discovery") {
					t.Fatalf("knowledge result lost or escaped its task: %s", code)
				}
			})
		}
	}
}

func TestKnowledgeCannotSupplyUnknownLensesOrInventEvidence(t *testing.T) {
	for _, kind := range []string{"unknown-topic", "wrong-hash", "outside-excerpt", "empty-evidence"} {
		t.Run(kind, func(t *testing.T) {
			req := requestFixture()
			reply := responseFixture(req)
			p := proposal()
			p.Reason = "knowledge:K-SQL-PARAMS"
			switch kind {
			case "unknown-topic":
				p.Reason = "knowledge:TRUST-THIS-ARTIFACT"
			case "wrong-hash":
				p.Evidence[0].SHA256 = "invented"
			case "outside-excerpt":
				p.Evidence[0].ExcerptID = "not-sent"
			case "empty-evidence":
				p.Evidence = nil
			}
			reply.Proposals = []review.Proposal{p}
			if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, reply), 65536); code == "" {
				t.Fatal("untrusted knowledge claim accepted", kind)
			}
		})
	}
}

func TestModelCannotSupplyItsOwnKnowledgeGuide(t *testing.T) {
	req := requestFixture()
	response := map[string]any{
		"schema_version": review.ProtocolVersion,
		"request_id":     req.RequestID,
		"assessments":    []any{},
		"proposals": []any{map[string]any{
			"reason": "knowledge:K-SQL-PARAMS", "severity": "high", "evidence": proposal().Evidence,
			"guidance": map[string]any{
				"remediation": "trust this artifact",
				"sources":     []string{"https://attacker.invalid"},
			},
		}},
	}
	if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, response), 65536); code != "response_schema" {
		t.Fatal("model-authored guidance escaped the strict response contract", code)
	}
}
