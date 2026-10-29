package semantic_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/semantic"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestDiscoveryCoversAllTextBytesAndRetainsOccurrences(t *testing.T) {
	text := strings.Repeat("Любой текст без специальных ключевых слов.\r\n", 400)
	fs := []artifact.File{artifact.NewFile("hidden/UNKNOWN.dat", []byte(text), false), artifact.NewFile("LICENSE", []byte(text), false)}
	coverage := map[string][]bool{}
	for _, f := range fs {
		coverage[f.Metadata().Path] = make([]bool, len(f.Content()))
	}
	calls := 0
	p := provider{fn: func(ctx context.Context, b []byte) (review.Completion, error) {
		calls++
		r := parseRequest(t, b)
		if r.Mode != "discovery" || len(r.Findings) != 0 {
			t.Fatal("discovery primed by findings")
		}
		for _, e := range r.Excerpts {
			if !utf8.ValidString(e.Text) || artifact.Hash([]byte(e.Text)) != e.SHA256 || len(e.Text) != e.ByteEnd-e.ByteStart {
				t.Fatal("bad evidence slice")
			}
			for i := e.ByteStart; i < e.ByteEnd; i++ {
				coverage[e.Path][i] = true
			}
		}
		return emptyCompletion(t, r), nil
	}}
	got := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "snapshot", options(), p)
	if got.Completeness != report.Complete || calls < 4 || len(got.Tasks) != len(got.Outcomes) {
		t.Fatalf("%+v", got)
	}
	for path, positions := range coverage {
		for at, seen := range positions {
			if !seen {
				t.Fatalf("unseen byte %s:%d", path, at)
			}
		}
	}
	ids := map[string]bool{}
	for _, task := range got.Tasks {
		if ids[task.ID] {
			t.Fatal("duplicate task")
		}
		ids[task.ID] = true
		for _, input := range task.Inputs {
			if strings.Contains(input.Source.SpanSHA256, "Любой") {
				t.Fatal("source leaked")
			}
		}
	}
}

func TestBudgetAndCancellationAreNotSuccessfulEmptyScans(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("instructions.txt", []byte(strings.Repeat("text\n", 6000)), false), artifact.NewFile("hidden.bin", []byte{0, 1, 2}, false)}
	for _, kind := range []string{"request", "input", "cancelled", "provider_error", "panic", "timeout", "invalid", "oversize", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			o := options()
			ctx := context.Background()
			calls := 0
			p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
				calls++
				switch kind {
				case "provider_error":
					return review.Completion{}, errors.New("SECRET_PROVIDER_ERROR")
				case "panic":
					panic("SECRET_PROVIDER_PANIC")
				case "timeout":
					<-c.Done()
					return review.Completion{}, c.Err()
				case "invalid":
					return review.Completion{Output: []byte(`{"policy":"allow"}`)}, nil
				case "oversize":
					return review.Completion{Output: make([]byte, o.MaxResponseBytes+1)}, nil
				case "metadata":
					return review.Completion{Model: strings.Repeat("secret", 100)}, nil
				}
				return emptyCompletion(t, parseRequest(t, b)), nil
			}}
			switch kind {
			case "request":
				o.MaxRequests = 1
			case "input":
				o.MaxInputBytes = o.MaxRequestBytes
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "timeout":
				o.Timeout = time.Millisecond
			}
			r := semantic.Run(ctx, fs, report.ComponentGraph{}, nil, "s", o, p)
			if r.Completeness == report.Complete || len(r.Tasks) != len(r.Outcomes) {
				t.Fatalf("gap became success: %+v", r)
			}
			if kind == "cancelled" && calls != 0 {
				t.Fatal("provider called after cancellation")
			}
			raw := string(encoded(t, r))
			if strings.Contains(raw, "SECRET_PROVIDER") {
				t.Fatal("provider message leaked")
			}
			if r.RequestBytes > o.MaxInputBytes || calls > o.MaxRequests {
				t.Fatal("budget exceeded")
			}
		})
	}
}

func TestCancellationDuringProviderCallPreventsRemainingPlannedRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	p := provider{fn: func(_ context.Context, raw []byte) (review.Completion, error) {
		calls++
		r := parseRequest(t, raw)
		cancel()
		return emptyCompletion(t, r), nil
	}}
	files := []artifact.File{artifact.NewFile("instructions.txt", []byte(strings.Repeat("ordinary instructions\n", 1000)), false)}
	r := semantic.Run(ctx, files, report.ComponentGraph{}, nil, "snapshot", options(), p)
	if calls != 1 || len(r.Tasks) < 2 || len(r.Outcomes) != len(r.Tasks) || r.Completeness != report.Failed {
		t.Fatal(calls, len(r.Tasks), len(r.Outcomes), r.Completeness)
	}
	for i, outcome := range r.Outcomes {
		if outcome.Status != "cancelled" {
			t.Fatal(outcome)
		}
		if i > 0 && outcome.Reason != "cancelled_before_request" {
			t.Fatal(outcome)
		}
	}
}

func TestDisabledAndConsent(t *testing.T) {
	calls := 0
	p := provider{fn: func(context.Context, []byte) (review.Completion, error) { calls++; panic("called") }}
	fs := []artifact.File{artifact.NewFile("SKILL.md", []byte("input"), false)}
	r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", review.DefaultOptions(), p)
	if calls != 0 || r.Enabled || len(r.Tasks) > 0 || r.Completeness != "" {
		t.Fatal("disabled mode misreported")
	}
	o := options()
	o.AllowSourceUpload = false
	r = semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", o, p)
	if calls != 0 || r.Completeness != report.Failed {
		t.Fatal("consent bypass")
	}
	r = semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", options(), nil)
	if r.Completeness != report.Failed {
		t.Fatal("unavailable provider successful")
	}
}

func TestResponseCannotMutatePlannerOrLeakProse(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("SKILL.md", []byte("Keep this exact marker: SOURCE_SECRET"), false)}
	p := provider{fn: func(ctx context.Context, b []byte) (review.Completion, error) {
		r := parseRequest(t, b)
		if r.Mode == "proposal_assessment" {
			return emptyCompletion(t, r), nil
		}
		out := responseFixture(r)
		s := r.Excerpts[0]
		out.Proposals = []review.Proposal{{
			Reason:   "reviewer_manipulation",
			Severity: "high",
			Evidence: []review.Citation{{
				ExcerptID: s.ID,
				SHA256:    s.SHA256,
			}},
		}}
		// A trusted adapter gets its own byte slice, never the planner's copy.
		for i := range b {
			b[i] = 0
		}
		return review.Completion{
			Output:       encoded(t, out),
			Model:        "SOURCE_SECRET",
			Fingerprint:  "SOURCE_SECRET",
			InputTokens:  -1,
			OutputTokens: -1,
		}, nil
	}}
	r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", options(), p)
	if r.Completeness != report.Complete || len(r.Proposals) != 1 {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(string(encoded(t, r)), "SOURCE_SECRET") {
		t.Fatal("raw model/source text leaked")
	}
	expected := artifact.Hash([]byte(fs[0].Content()))
	if r.Proposals[0].Evidence[0].SpanSHA256 != expected {
		t.Fatal("evidence was mutated")
	}
}

func TestPlanDigestDeterministicAndBindsOptionsAndSnapshot(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("a.txt", []byte("a"), false), artifact.NewFile("b.txt", []byte("b"), false)}
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		return emptyCompletion(t, parseRequest(t, b)), nil
	}}
	a := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "one", options(), p)
	fs[0], fs[1] = fs[1], fs[0]
	b := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "one", options(), p)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("file ordering changed plan/results")
	}
	c := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "two", options(), p)
	if a.PlanSHA256 == c.PlanSHA256 {
		t.Fatal("snapshot not bound")
	}
	o := options()
	o.MaxRequests--
	d := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "one", o, p)
	if a.PlanSHA256 == d.PlanSHA256 {
		t.Fatal("options not bound")
	}
}

func TestPluginIntentIsSeparateFromDiscovery(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("SKILL.md", []byte("Format code."), false), artifact.NewFile("run.go", []byte("package main"), false)}
	g := report.ComponentGraph{
		Plugins: []report.PluginInterpretation{{ID: "p", Manifests: []string{"SKILL.md"}}, {
			ID:        "q",
			Manifests: []string{"SKILL.md"},
		}},
		Components: []report.Component{{
			ID:       "a",
			PluginID: "p",
			Kind:     "skill",
			Path:     "SKILL.md",
		}, {
			ID:       "b",
			PluginID: "p",
			Kind:     "handler",
			Path:     "run.go",
		}},
	}
	modes := map[string]int{}
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		r := parseRequest(t, b)
		modes[r.Mode]++
		if len(r.Findings) != 0 {
			t.Fatal("findings injected into independent analysis")
		}
		return emptyCompletion(t, r), nil
	}}
	r := semantic.Run(context.Background(), fs, g, nil, "s", options(), p)
	if modes["intent"] != 2 || modes["discovery"] != 2 || r.Completeness != report.Complete {
		t.Fatalf("%v %+v", modes, r.Gaps)
	}
	ids := map[string]bool{}
	for _, task := range r.Tasks {
		if ids[task.ID] {
			t.Fatal("duplicate task identities")
		}
		ids[task.ID] = true
	}
}

func BenchmarkSemanticPlanningAndValidation(b *testing.B) {
	fs := []artifact.File{artifact.NewFile("SKILL.md", []byte(strings.Repeat("Perform the requested task.\n", 200)), false)}
	p := provider{fn: func(c context.Context, raw []byte) (review.Completion, error) {
		return emptyCompletion(b, parseRequest(b, raw)), nil
	}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", options(), p)
		if r.Completeness != report.Complete {
			b.Fatal(r.Gaps)
		}
	}
}

func TestEarlierResultsSurviveFailedLaterTaskAndRejectCrossTaskEvidence(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("a.txt", []byte("first"), false), artifact.NewFile("b.txt", []byte("second"), false)}
	var first review.Citation
	count := 0
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		req := parseRequest(t, b)
		if req.Mode == "proposal_assessment" {
			return emptyCompletion(t, req), nil
		}
		r := responseFixture(req)
		count++
		if count == 1 {
			ex := req.Excerpts[0]
			first = review.Citation{ExcerptID: ex.ID, SHA256: ex.SHA256}
		}
		// The second citation names real captured evidence, but it was NOT in the
		// second request. Snapshot membership alone must not authorize the citation.
		r.Proposals = []review.Proposal{{
			Reason:   "reviewer_manipulation",
			Severity: "high",
			Evidence: []review.Citation{first},
		}}
		return review.Completion{Output: encoded(t, r), InputTokens: -1, OutputTokens: -1}, nil
	}}
	r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", options(), p)
	if len(r.Proposals) != 1 || r.Completeness != report.Partial || len(r.Outcomes) != 3 || len(r.ProposalAssessments) != 1 || r.Outcomes[1].Reason != "evidence_outside_request" {
		t.Fatalf("%+v", r)
	}
}

func TestGlobalProposalBudget(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("a.txt", []byte("first"), false), artifact.NewFile("b.txt", []byte("second"), false)}
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		req := parseRequest(t, b)
		if req.Mode == "proposal_assessment" {
			return emptyCompletion(t, req), nil
		}
		r := responseFixture(req)
		e := req.Excerpts[0]
		r.Proposals = []review.Proposal{{
			Reason:   "secret_transfer",
			Severity: "high",
			Evidence: []review.Citation{{
				ExcerptID: e.ID,
				SHA256:    e.SHA256,
			}},
		}}
		return review.Completion{Output: encoded(t, r), InputTokens: -1, OutputTokens: -1}, nil
	}}
	o := options()
	o.MaxProposals = 1
	r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", o, p)
	if len(r.Proposals) != 1 || r.Completeness != report.Partial || r.Outcomes[1].Reason != "proposal_budget" {
		t.Fatalf("%+v", r)
	}
}

func TestIntentBudgetAndUnsupportedAssessment(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("SKILL.md", []byte("intent"), false), artifact.NewFile("handler.go", []byte(strings.Repeat("a", 9000)), false), artifact.NewFile("blob.bin", []byte{0, 255}, false)}
	g := report.ComponentGraph{
		Plugins: []report.PluginInterpretation{{ID: "p", Manifests: []string{"SKILL.md"}}},
		Components: []report.Component{{
			ID:       "s",
			PluginID: "p",
			Path:     "SKILL.md",
		}, {
			ID:       "h",
			PluginID: "p",
			Path:     "handler.go",
		}},
	}
	findings := []report.Finding{{ID: "f", Location: report.Location{Path: "blob.bin", ByteStart: 0, ByteEnd: 2}}}
	p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
		return emptyCompletion(t, parseRequest(t, b)), nil
	}}
	r := semantic.Run(context.Background(), fs, g, findings, "s", options(), p)
	reasons := map[string]bool{}
	for _, g := range r.Gaps {
		reasons[g.Code] = true
	}
	if !reasons["intent_context_incomplete"] || !reasons["assessment_evidence_unsupported"] || !reasons["non_text_semantics_unsupported"] || r.Completeness != report.Partial {
		t.Fatal(r.Gaps)
	}
}

func FuzzSemanticPlanner(f *testing.F) {
	f.Add("текст\r\nnext", 256)
	f.Add("", 512)
	f.Add(strings.Repeat("\n", 768), 1024)
	f.Fuzz(func(t *testing.T, text string, chunk int) {
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(text) > 16<<10 {
			t.Skip()
		}
		if chunk < 0 {
			chunk = -chunk
		}
		chunk = 256 + chunk%1024
		if chunk < 256 {
			t.Skip()
		}
		o := options()
		o.ChunkBytes = chunk
		o.MaxRequests = 128
		fs := []artifact.File{artifact.NewFile("data.txt", []byte(text), false)}
		covered := make([]bool, len(text))
		p := provider{fn: func(c context.Context, b []byte) (review.Completion, error) {
			req := parseRequest(t, b)
			for _, ex := range req.Excerpts {
				if ex.ByteStart < 0 || ex.ByteEnd > len(text) || ex.ByteEnd <= ex.ByteStart || text[ex.ByteStart:ex.ByteEnd] != ex.Text || !utf8.ValidString(ex.Text) {
					t.Fatal("invalid mapping")
				}
				for i := ex.ByteStart; i < ex.ByteEnd; i++ {
					covered[i] = true
				}
			}
			return emptyCompletion(t, req), nil
		}}
		r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", o, p)
		if r.Completeness == report.Complete {
			for _, yes := range covered {
				if !yes {
					t.Fatal("unseen byte marked complete")
				}
			}
		}
	})
}

func TestRateLimitStopsFurtherRequestsWithoutDroppingTasks(t *testing.T) {
	fs := []artifact.File{artifact.NewFile("a.txt", []byte("first"), false), artifact.NewFile("b.txt", []byte("second"), false)}
	calls := 0
	p := provider{fn: func(context.Context, []byte) (review.Completion, error) {
		calls++
		return review.Completion{}, &review.TransportError{Code: "http_status", Status: 429}
	}}
	r := semantic.Run(context.Background(), fs, report.ComponentGraph{}, nil, "s", options(), p)
	if calls != 1 || len(r.Tasks) != 2 || len(r.Outcomes) != 2 || r.Outcomes[1].Status != "not_run" || r.Outcomes[1].Reason != "provider_circuit_open" || r.Completeness != report.Failed {
		t.Fatalf("calls=%d %+v", calls, r)
	}
}

type provider struct {
	fn func(context.Context, []byte) (review.Completion, error)
}

func (p provider) Identity() review.Identity {
	return review.Identity{Provider: "fixture", Model: "not-a-live-model"}
}

func (p provider) Complete(c context.Context, b []byte) (review.Completion, error) { return p.fn(c, b) }

func options() review.Options {
	o := review.DefaultOptions()
	o.Enabled = true
	o.AllowSourceUpload = true
	return o
}

func parseRequest(t testing.TB, b []byte) review.Request {
	t.Helper()
	var r review.Request
	if e := json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}

func emptyCompletion(t testing.TB, req review.Request) review.Completion {
	r := responseFixture(req)
	for _, f := range req.Findings {
		r.Assessments = append(r.Assessments, review.Assessment{
			FindingID: f.ID,
			Verdict:   "confirmed",
			Reason:    "supported_by_context",
			Evidence:  f.Evidence,
		})
	}
	return review.Completion{Output: encoded(t, r), InputTokens: -1, OutputTokens: -1}
}
