package semantic_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestQualityPolicyIsSeparateAndReassessed(t *testing.T) {
	o := options()
	o.QualityPolicy = true
	seen := map[string]int{}
	p := provider{fn: func(ctx context.Context, b []byte) (review.Completion, error) {
		r := parseRequest(t, b)
		seen[r.Mode]++
		reply := responseFixture(r)
		if r.Mode == "quality" {
			reply.Proposals = []review.Proposal{{
				Reason:   "quality_vague_triggers",
				Severity: "low",
				Evidence: []review.Citation{{
					ExcerptID: r.Excerpts[0].ID,
					SHA256:    r.Excerpts[0].SHA256,
				}},
			}}
		} else {
			return emptyCompletion(t, r), nil
		}
		return review.Completion{Output: encoded(t, reply)}, nil
	}}
	r := semantic.Run(context.Background(), []artifact.File{artifact.NewFile("SKILL.md", []byte("Run when needed."), false)}, report.ComponentGraph{}, nil, "s", o, p)
	if seen["quality"] != 1 || seen["proposal_assessment"] != 1 || len(r.Proposals) != 1 || len(r.ProposalAssessments) != 1 {
		t.Fatalf("%+v %+v", seen, r)
	}
	if r.Proposals[0].Category != "quality_policy" {
		t.Fatal(r.Proposals)
	}
	req := requestFixture()
	reply := responseFixture(req)
	q := proposal()
	q.Reason = "quality_vague_triggers"
	reply.Proposals = []review.Proposal{q}
	if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, reply), 65536); code == "" {
		t.Fatal("quality was accepted as discovery")
	}
}

func TestResponseSchemaMatchesProtocol(t *testing.T) {
	schema := review.ResponseSchema()
	props := schema["properties"].(map[string]any)
	version := props["schema_version"].(map[string]any)["enum"].([]any)[0]
	if version != review.ProtocolVersion {
		t.Fatalf("schema=%v protocol=%s", version, review.ProtocolVersion)
	}
}
