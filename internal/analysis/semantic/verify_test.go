package semantic_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestProposalVerificationHasSeparatePlanAndOriginalContext(t *testing.T) {
	for _, verdict := range []string{"confirmed", "disputed", "insufficient_context"} {
		t.Run(verdict, func(t *testing.T) {
			files := []artifact.File{artifact.NewFile("LICENSE", []byte("Context before.\nSOURCE_SENTINEL\nContext after."), false)}
			var initial review.Request
			calls := 0
			p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
				calls++
				req := parseRequest(t, b)
				out := responseFixture(req)
				switch req.Mode {
				case "discovery":
					initial = req
					if len(req.Findings) != 0 {
						t.Fatal("discovery is primed")
					}
					ex := req.Excerpts[0]
					out.Proposals = []review.Proposal{{
						Reason:   "reviewer_manipulation",
						Severity: "high",
						Evidence: []review.Citation{{
							ExcerptID: ex.ID,
							SHA256:    ex.SHA256,
						}},
					}}
				case "proposal_assessment":
					if req.ParentTaskID != initial.RequestID || !reflect.DeepEqual(req.Excerpts, initial.Excerpts) || !reflect.DeepEqual(req.Links, initial.Links) || len(req.Findings) != 1 {
						t.Fatal("second pass lost the original bounded source context")
					}
					f := req.Findings[0]
					if f.Origin != "semantic_proposal" || f.Reason != "reviewer_manipulation" || f.RuleID != "" {
						t.Fatal("hypothesis masquerades as a static fact")
					}
					reason := "supported_by_context"
					if verdict == "disputed" {
						reason = "benign_example"
					}
					if verdict == "insufficient_context" {
						reason = verdict
					}
					out.Assessments = []review.Assessment{{
						FindingID: f.ID,
						Verdict:   verdict,
						Reason:    reason,
						Evidence:  f.Evidence,
					}}
				default:
					t.Fatalf("unexpected recursive mode %s", req.Mode)
				}
				return review.Completion{Output: encoded(t, out), InputTokens: -1, OutputTokens: -1}, nil
			}}
			r := semantic.Run(context.Background(), files, report.ComponentGraph{}, nil, "snapshot", options(), p)
			if calls != 2 || len(r.Tasks) != 2 || len(r.Outcomes) != 2 || len(r.Proposals) != 1 || len(r.ProposalAssessments) != 1 || len(r.Assessments) != 0 {
				t.Fatalf("missing second pass: %+v", r)
			}
			if r.PlanSHA256 == "" || r.VerificationPlanSHA256 == "" || r.PlanSHA256 == r.VerificationPlanSHA256 {
				t.Fatal("phase hashes are not distinct")
			}
			if r.Tasks[1].DependsOn[0] != r.Tasks[0].ID || r.Tasks[1].ProposalIDs[0] != r.Proposals[0].ID || len(r.Tasks[1].FindingIDs) != 0 {
				t.Fatal("task provenance lost")
			}
			if r.ProposalAssessments[0].ProposalID != r.Proposals[0].ID || r.ProposalAssessments[0].Verdict != verdict || r.Proposals[0].SuggestedSeverity != report.High {
				t.Fatal("hypothesis changed by assessment")
			}
			want := report.Complete
			if verdict == "insufficient_context" {
				want = report.Partial
			}
			if r.Completeness != want {
				t.Fatal(r.Completeness)
			}
			if strings.Contains(string(encoded(t, r)), "SOURCE_SENTINEL") {
				t.Fatal("report leaks source")
			}
		})
	}
}

func TestVerificationBudgetsAreSharedAcrossPhases(t *testing.T) {
	for _, kind := range []string{"requests", "bytes", "cancelled", "second_pass_failure", "wrong_target", "recursive_proposal"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs := []artifact.File{artifact.NewFile("data.txt", []byte(strings.Repeat("Untrusted ordinary text.\n", 200)), false)}
			if kind == "cancelled" {
				fs = append(fs, artifact.NewFile("z.txt", []byte("a later request"), false))
			}
			o := options()
			if kind == "requests" {
				o.MaxRequests = 1
			}
			if kind == "bytes" {
				o.MaxRequestBytes = 16384
				o.MaxInputBytes = 16384
			}
			calls, sent := 0, 0
			p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
				calls++
				sent += len(b)
				req := parseRequest(t, b)
				out := responseFixture(req)
				if req.Mode == "discovery" {
					ex := req.Excerpts[0]
					out.Proposals = []review.Proposal{{
						Reason:   "secret_transfer",
						Severity: "high",
						Evidence: []review.Citation{{
							ExcerptID: ex.ID,
							SHA256:    ex.SHA256,
						}},
					}}
					if kind == "bytes" {
						// Each distinct hypothesis must be reviewed; the aggregate
						// budget must not reset for these second-stage requests.
						for _, reason := range []string{"instruction_override", "reviewer_manipulation", "untrusted_dependency"} {
							x := out.Proposals[0]
							x.Reason = reason
							out.Proposals = append(out.Proposals, x)
						}
					}
				} else {
					if kind == "second_pass_failure" {
						return review.Completion{}, &review.TransportError{Code: "http_status", Status: 429}
					}
					for _, f := range req.Findings {
						out.Assessments = append(out.Assessments, review.Assessment{
							FindingID: f.ID,
							Verdict:   "confirmed",
							Reason:    "supported_by_context",
							Evidence:  f.Evidence,
						})
					}
					if kind == "wrong_target" {
						out.Assessments[0].FindingID = "invented-proposal"
					}
					if kind == "recursive_proposal" {
						out.Proposals = []review.Proposal{{
							Reason:   "secret_transfer",
							Severity: "high",
							Evidence: req.Findings[0].Evidence,
						}}
					}
				}
				return review.Completion{Output: encoded(t, out), InputTokens: -1, OutputTokens: -1}, nil
			}}
			// Cancel during a later discovery call, after the first response was
			// accepted. No verification call may start on the cancelled context.
			if kind == "cancelled" {
				old := p.fn
				p.fn = func(c context.Context, b []byte) (review.Completion, error) {
					result, err := old(c, b)
					if calls == 2 {
						cancel()
					}
					return result, err
				}
			}
			r := semantic.Run(ctx, fs, report.ComponentGraph{}, nil, "snapshot", o, p)
			if r.Completeness == report.Complete || len(r.Tasks) != len(r.Outcomes) {
				t.Fatal("failed/omitted verification hidden")
			}
			if len(r.Proposals) == 0 {
				t.Fatal("first-stage proposal lost")
			}
			if calls > o.MaxRequests || sent > o.MaxInputBytes || r.RequestBytes != sent {
				t.Fatal("phase budget reset")
			}
			if kind == "requests" && (calls != 1 || len(r.Gaps) != 1 || r.Gaps[0].ProposalID != r.Proposals[0].ID) {
				t.Fatal("missing verification obligation")
			}
		})
	}
}

func TestSecondPlanBindsProposalsButDoesNotRewriteInitialPlan(t *testing.T) {
	run := func(reason string) report.SemanticReport {
		p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
			req := parseRequest(t, b)
			if req.Mode == "proposal_assessment" {
				return emptyCompletion(t, req), nil
			}
			out := responseFixture(req)
			e := req.Excerpts[0]
			out.Proposals = []review.Proposal{{
				Reason:   reason,
				Severity: "medium",
				Evidence: []review.Citation{{
					ExcerptID: e.ID,
					SHA256:    e.SHA256,
				}},
			}}
			return review.Completion{Output: encoded(t, out), InputTokens: -1, OutputTokens: -1}, nil
		}}
		return semantic.Run(context.Background(), []artifact.File{artifact.NewFile("a", []byte("same bytes"), false)}, report.ComponentGraph{}, nil, "same", options(), p)
	}
	a, b := run("secret_transfer"), run("instruction_override")
	if a.PlanSHA256 != b.PlanSHA256 || a.VerificationPlanSHA256 == b.VerificationPlanSHA256 {
		t.Fatal("phase bindings incorrect")
	}
	if !reflect.DeepEqual(a, run("secret_transfer")) {
		t.Fatal("synthetic deterministic result changed")
	}
}

func TestProposalModeRejectsStaticNamespaceAndWrongProtocol(t *testing.T) {
	req := requestFixture()
	req.Mode = "proposal_assessment"
	req.Findings = []review.Finding{{ID: "proposal-id", Origin: "semantic_proposal", Evidence: proposal().Evidence}}
	response := responseFixture(req)
	response.Assessments = []review.Assessment{{
		FindingID: "static-id",
		Verdict:   "confirmed",
		Reason:    "supported_by_context",
		Evidence:  proposal().Evidence,
	}}
	if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, response), 65536); code != "unknown_or_duplicate_finding" {
		t.Fatal(code)
	}
	response.Assessments[0].FindingID = "proposal-id"
	response.SchemaVersion = "1"
	if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, response), 65536); code != "response_identity_mismatch" {
		t.Fatal(code)
	}
	// The protocol version is mirrored by the actual HTTP JSON Schema.
	b, _ := json.Marshal(review.ResponseSchema())
	if !strings.Contains(string(b), `"enum":["`+review.ProtocolVersion+`"]`) {
		t.Fatal("old HTTP schema")
	}
}

func TestSameTextInDifferentObjectsKeepsSeparateProposalReviews(t *testing.T) {
	files := []artifact.File{artifact.NewFile("a.txt", []byte("same text"), false), artifact.NewFile("b.txt", []byte("same text"), false)}
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		req := parseRequest(t, b)
		if req.Mode == "proposal_assessment" {
			return emptyCompletion(t, req), nil
		}
		out := responseFixture(req)
		e := req.Excerpts[0]
		out.Proposals = []review.Proposal{{
			Reason:   "secret_transfer",
			Severity: "high",
			Evidence: []review.Citation{{
				ExcerptID: e.ID,
				SHA256:    e.SHA256,
			}},
		}}
		return review.Completion{Output: encoded(t, out), InputTokens: -1, OutputTokens: -1}, nil
	}}
	got := semantic.Run(context.Background(), files, report.ComponentGraph{}, nil, "snapshot", options(), p)
	if got.Completeness != report.Complete || len(got.Proposals) != 2 || len(got.ProposalAssessments) != 2 || got.InitialTaskCount != 2 || len(got.Tasks) != 4 {
		t.Fatal("occurrences lost")
	}
	if got.Proposals[0].ID == got.Proposals[1].ID || got.ProposalAssessments[0].ProposalID == got.ProposalAssessments[1].ProposalID {
		t.Fatal("same-text objects collapsed")
	}
	for _, p := range got.Proposals {
		found := false
		for _, a := range got.ProposalAssessments {
			if a.ProposalID == p.ID {
				found = true
				if !reflect.DeepEqual(a.Evidence, p.Evidence) {
					t.Fatal("cross-object proof substitution")
				}
			}
		}
		if !found {
			t.Fatal("unreviewed occurrence")
		}
	}
}

func BenchmarkTwoPhaseSemanticReview(b *testing.B) {
	files := []artifact.File{artifact.NewFile("SKILL.md", []byte(strings.Repeat("Untrusted agent instructions.\n", 100)), false)}
	p := provider{fn: func(c context.Context, raw []byte) (review.Completion, error) {
		req := parseRequest(b, raw)
		if req.Mode == "proposal_assessment" {
			return emptyCompletion(b, req), nil
		}
		out := responseFixture(req)
		e := req.Excerpts[0]
		out.Proposals = []review.Proposal{{
			Reason:   "instruction_override",
			Severity: "medium",
			Evidence: []review.Citation{{
				ExcerptID: e.ID,
				SHA256:    e.SHA256,
			}},
		}}
		return review.Completion{Output: encoded(b, out), InputTokens: -1, OutputTokens: -1}, nil
	}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got := semantic.Run(context.Background(), files, report.ComponentGraph{}, nil, "snapshot", options(), p)
		if got.Completeness != report.Complete || len(got.ProposalAssessments) != 1 {
			b.Fatal("incomplete benchmark")
		}
	}
}
