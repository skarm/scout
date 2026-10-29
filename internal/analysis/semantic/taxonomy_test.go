package semantic_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestSpecializedTaxonomyCannotChangeReviewStage(t *testing.T) {
	for _, mode := range []string{"discovery", "intent", "quality"} {
		for _, reason := range []string{"semantic_prompt_injection", "paraphrased_attack", "natural_language_exfiltration", "gradual_deception", "description_behavior_mismatch", "context_inappropriate_capability", "declared_scope_creep", "intent_code_divergence", "quality_vague_triggers", "quality_missing_warnings", "quality_language_policy"} {
			t.Run(mode+"/"+reason, func(t *testing.T) {
				r := requestFixture()
				r.Mode = mode
				r.Excerpts[0].Path = "SKILL.md"
				reply := responseFixture(r)
				q := proposal()
				q.Reason = reason
				reply.Proposals = []review.Proposal{q}
				_, code := semantic.ValidateResponse(context.Background(), r, encoded(t, reply), 65536)
				if (code == "") != (knowledge.ReasonMode(reason) == mode) {
					t.Fatalf("code=%s", code)
				}
			})
		}
	}
}

func TestQualityFileApplicabilityIsValidated(t *testing.T) {
	for _, tc := range []struct {
		path, text, reason string
		valid              bool
	}{
		{path: "handler.py", text: "print(1)", reason: "quality_vague_triggers", valid: false},
		{path: "handler.go", text: "package p", reason: "quality_vague_triggers", valid: false},
		{path: "SKILL.md", text: "Use when needed.", reason: "quality_vague_triggers", valid: true},
		{path: "config.json", text: "{}", reason: "quality_vague_triggers", valid: true},
		{path: "anything.unknown", text: "unknown", reason: "quality_vague_triggers", valid: false},
		{path: "notes.txt", text: "#!/usr/bin/env python3\nprint(1)", reason: "quality_vague_triggers", valid: false},
		{path: "notes.txt", text: "A description.", reason: "quality_missing_warnings", valid: false},
		{path: "handler.py", text: "print(1)", reason: "quality_missing_warnings", valid: true},
		{path: "config.yaml", text: "key: value", reason: "quality_language_policy", valid: true},
	} {
		t.Run(tc.path+"/"+tc.reason, func(t *testing.T) {
			r := requestFixture()
			r.Mode = "quality"
			r.Excerpts[0].Path = tc.path
			r.Excerpts[0].Text = tc.text
			reply := responseFixture(r)
			q := proposal()
			q.Reason = tc.reason
			reply.Proposals = []review.Proposal{q}
			_, code := semantic.ValidateResponse(context.Background(), r, encoded(t, reply), 65536)
			if (code == "") != tc.valid {
				t.Fatal(code)
			}
		})
	}
}

func TestSpecializedProposalCarriesTaxonomyAndRecheckGuidance(t *testing.T) {
	o := options()
	seen := map[string]int{}
	p := provider{fn: func(ctx context.Context, b []byte) (review.Completion, error) {
		req := parseRequest(t, b)
		seen[req.Mode]++
		pd, _ := knowledge.Describe(req.Mode)
		if req.PromptSHA256 != pd.SHA256 {
			t.Error("incorrect prompt identity")
		}
		if req.Mode == "discovery" {
			out := responseFixture(req)
			ex := req.Excerpts[0]
			out.Proposals = []review.Proposal{{
				Reason:   "natural_language_exfiltration",
				Severity: "high",
				Evidence: []review.Citation{{
					ExcerptID: ex.ID,
					SHA256:    ex.SHA256,
				}},
			}}
			return review.Completion{Output: encoded(t, out)}, nil
		}
		if req.Mode == "proposal_assessment" {
			if len(req.Findings) != 1 || req.Findings[0].Guidance == nil || len(req.Findings[0].Guidance.ReviewChecks) == 0 {
				t.Error("missing original rule review instructions")
			}
		}
		return emptyCompletion(t, req), nil
	}}
	r := semantic.Run(context.Background(), []artifact.File{artifact.NewFile("SKILL.md", []byte("Synthetic protocol test, not an attack detection benchmark."), false)}, report.ComponentGraph{}, nil, "snapshot", o, p)
	if len(r.Proposals) != 1 || r.Proposals[0].UpstreamRuleID != "SSD-3" || seen["proposal_assessment"] != 1 {
		t.Fatalf("%+v %+v", r.Proposals, seen)
	}
	if r.InstructionPack.SHA256 != knowledge.Inventory().SHA256 {
		t.Fatal("missing pack identity")
	}
	for _, task := range r.Tasks {
		pd, _ := knowledge.Describe(task.Mode)
		if task.PromptSHA256 != pd.SHA256 || task.PromptBytes != pd.Bytes {
			t.Fatalf("missing task prompt metadata: %+v", task)
		}
	}
}
