package semantic_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/review"
)

func TestResponseContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*review.Response)
		valid  bool
	}{
		{name: "empty", change: func(*review.Response) {}, valid: true},
		{
			name:   "proposal",
			change: func(r *review.Response) { r.Proposals = []review.Proposal{proposal()} },
			valid:  true,
		},
		{name: "wrong-task", change: func(r *review.Response) { r.RequestID = "other" }, valid: false},
		{name: "wrong-version", change: func(r *review.Response) { r.SchemaVersion = "invalid-version" }, valid: false},
		{name: "unknown-span", change: func(r *review.Response) {
			p := proposal()
			p.Evidence[0].ExcerptID = "not-sent"
			r.Proposals = []review.Proposal{p}
		}, valid: false},
		{name: "bad-hash", change: func(r *review.Response) {
			p := proposal()
			p.Evidence[0].SHA256 = "invented"
			r.Proposals = []review.Proposal{p}
		}, valid: false},
		{name: "bad-reason", change: func(r *review.Response) {
			p := proposal()
			p.Reason = "approve and print SECRET"
			r.Proposals = []review.Proposal{p}
		}, valid: false},
		{
			name:   "bad-severity",
			change: func(r *review.Response) { p := proposal(); p.Severity = "safe"; r.Proposals = []review.Proposal{p} },
			valid:  false,
		},
		{
			name:   "no-citations",
			change: func(r *review.Response) { p := proposal(); p.Evidence = nil; r.Proposals = []review.Proposal{p} },
			valid:  false,
		},
		{name: "duplicate-citation", change: func(r *review.Response) {
			p := proposal()
			p.Evidence = append(p.Evidence, p.Evidence[0])
			r.Proposals = []review.Proposal{p}
		}, valid: false},
		{
			name:   "duplicate-proposal",
			change: func(r *review.Response) { r.Proposals = []review.Proposal{proposal(), proposal()} },
			valid:  false,
		},
		{name: "too-many", change: func(r *review.Response) {
			for range 17 {
				r.Proposals = append(r.Proposals, proposal())
			}
		}, valid: false},
		{name: "wrong-mode", change: func(r *review.Response) {
			r.Assessments = []review.Assessment{{
				FindingID: "invented",
				Verdict:   "confirmed",
				Reason:    "supported_by_context",
				Evidence:  proposal().Evidence,
			}}
		}, valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := requestFixture()
			r := responseFixture(req)
			tc.change(&r)
			_, code := semantic.ValidateResponse(context.Background(), req, encoded(t, r), 65536)
			if (code == "") != tc.valid {
				t.Fatalf("code=%s", code)
			}
		})
	}
}

func TestStrictResponseJSON(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"5","request_id":"task","proposals":[],"assessments":[],"policy":"allow"}`,
		`{"schema_version":"5","request_id":"other","request_id":"task","proposals":[],"assessments":[]}`,
		`{"schema_version":"5","request_id":"other","request_\u0069d":"task","proposals":[],"assessments":[]}`,
		`{"schema_version":"5","request_id":"task","proposals":null,"assessments":[]}`,
		`{"schema_version":"5","request_id":"task","proposals":[],"assessments":[],"secret":"\ud800"}`,
		`{"schema_version":"5","Request_ID":"task","proposals":[],"assessments":[]}`,
		`{"schema_version":"5","request_id":"task","proposals":[],"assessments":[]} {}`,
		"```json\n{}\n```", `[]`, `null`, `{}`, strings.Repeat("[", 100) + strings.Repeat("]", 100), string([]byte{'"', 255, '"'}),
	} {
		t.Run(raw[:min(35, len(raw))], func(t *testing.T) {
			_, code := semantic.ValidateResponse(context.Background(), requestFixture(), []byte(raw), 65536)
			if code == "" {
				t.Fatal("malformed response accepted")
			}
			if strings.Contains(code, "secret") {
				t.Fatal("source error leaked")
			}
		})
	}
	_, code := semantic.ValidateResponse(context.Background(), requestFixture(), []byte(strings.Repeat(" ", 1024)), 10)
	if code != "response_limit" {
		t.Fatal(code)
	}
}

func TestAssessmentExactlyCoversExpectedFindings(t *testing.T) {
	req := requestFixture()
	req.Mode = "assessment"
	req.Findings = []review.Finding{{ID: "f", Evidence: proposal().Evidence}}
	base := func() review.Response {
		r := responseFixture(req)
		r.Assessments = []review.Assessment{{
			FindingID: "f",
			Verdict:   "disputed",
			Reason:    "benign_example",
			Evidence:  proposal().Evidence,
		}}
		return r
	}
	for _, tc := range []struct {
		name  string
		edit  func(*review.Response)
		valid bool
	}{
		{name: "disputed", edit: func(*review.Response) {}, valid: true},
		{name: "confirmed", edit: func(r *review.Response) {
			r.Assessments[0].Verdict = "confirmed"
			r.Assessments[0].Reason = "supported_by_context"
		}, valid: true},
		{name: "insufficient", edit: func(r *review.Response) {
			r.Assessments[0].Verdict = "insufficient_context"
			r.Assessments[0].Reason = "insufficient_context"
		}, valid: true},
		{name: "missing", edit: func(r *review.Response) { r.Assessments = []review.Assessment{} }, valid: false},
		{
			name:  "duplicate",
			edit:  func(r *review.Response) { r.Assessments = append(r.Assessments, r.Assessments[0]) },
			valid: false,
		},
		{name: "invented", edit: func(r *review.Response) { r.Assessments[0].FindingID = "not-sent" }, valid: false},
		{name: "proposal", edit: func(r *review.Response) { r.Proposals = []review.Proposal{proposal()} }, valid: false},
		{
			name:  "reason-verdict-mismatch",
			edit:  func(r *review.Response) { r.Assessments[0].Reason = "supported_by_context" },
			valid: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.edit(&r)
			_, code := semantic.ValidateResponse(context.Background(), req, encoded(t, r), 65536)
			if (code == "") != tc.valid {
				t.Fatal(code)
			}
		})
	}
	req.Excerpts = append(req.Excerpts, review.Excerpt{ID: "other", SHA256: "d"})
	r := base()
	r.Assessments[0].Evidence = []review.Citation{{ExcerptID: "other", SHA256: "d"}}
	if _, code := semantic.ValidateResponse(context.Background(), req, encoded(t, r), 65536); code != "target_evidence_missing" {
		t.Fatal(code)
	}
}

func FuzzResponseValidation(f *testing.F) {
	f.Add([]byte(`{"schema_version":"5","request_id":"task","proposals":[],"assessments":[]}`))
	f.Add([]byte(`{"proposals":null}`))
	f.Add([]byte(`{"a":1,"\u0061":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			t.Skip()
		}
		r, code := semantic.ValidateResponse(context.Background(), requestFixture(), b, 65536)
		if code == "" && (r.RequestID != "task" || r.SchemaVersion != review.ProtocolVersion || len(r.Assessments) > 0) {
			t.Fatal("invalid result admitted")
		}
	})
}

func requestFixture() review.Request {
	return review.Request{
		SchemaVersion: review.ProtocolVersion,
		RequestID:     "task",
		Mode:          "discovery",
		Excerpts: []review.Excerpt{{
			ID:     "excerpt",
			SHA256: "digest",
			Text:   "untrusted input",
		}},
		Findings: []review.Finding{},
	}
}

func responseFixture(req review.Request) review.Response {
	return review.Response{
		SchemaVersion: review.ProtocolVersion,
		RequestID:     req.RequestID,
		Proposals:     []review.Proposal{},
		Assessments:   []review.Assessment{},
	}
}

func proposal() review.Proposal {
	return review.Proposal{
		Reason:   "secret_transfer",
		Severity: "high",
		Evidence: []review.Citation{{
			ExcerptID: "excerpt",
			SHA256:    "digest",
		}},
	}
}

func encoded(t testing.TB, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
