package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skarm/scout/report"
)

func TestBundledReleaseRanges(t *testing.T) {
	for _, tc := range []struct {
		ecosystem, name, version string
		matches                  bool
	}{
		{"npm", "lodash", "4.17.20", true},
		{"npm", "lodash", "4.17.21", false},
		{"npm", "minimist", "0.2.0", true},
		{"npm", "minimist", "0.2.1", false},
		{"npm", "minimist", "1.0.0", true},
		{"npm", "minimist", "1.2.3", false},
		{"PyPI", "Requests", "2.31", true},
		{"PyPI", "requests", "2.31.0.1", true},
		{"PyPI", "requests", "2.32.0rc1", false},
		{"PyPI", "pip", "25.2", true},
		{"PyPI", "pip", "25.2.0.0", true},
		{"PyPI", "pip", "25.2.0.1", false},
		{"PyPI", "pip", "25.2.1", false},
		{"Go", "golang.org/x/net", "v0.3.0", true},
		{"Go", "golang.org/x/net", "v0.4.0", false},
	} {
		if got := bundledMatches(tc.ecosystem, tc.name, tc.version); (len(got) == 1) != tc.matches {
			t.Errorf("%+v: got %+v", tc, got)
		}
	}
}

func TestBundledFallbackPreservesCoverageAndSourcePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, response, status string
		providerStatus         int
		operatorCache          bool
	}{
		{"offline", "", "bundled_match", 0, false},
		{"unavailable provider", "", "bundled_match", 503, false},
		{"bad response", `{}`, "bundled_match", 200, false},
		{"healthy provider", `{"results":[{},{}]}`, report.OutcomeCompleted, 200, false},
		{"operator cache", "", report.OutcomeCached, 0, true},
		{"operator cache after bad response", `{}`, report.OutcomeCached, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			o := DefaultOptions()
			o.Enabled = true
			if tc.providerStatus != 0 {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.providerStatus)
					_, _ = w.Write([]byte(tc.response))
				}))
				defer server.Close()

				o.AllowNetwork, o.AllowLoopback, o.Endpoint = true, true, server.URL
			}

			if tc.operatorCache {
				o.Offline, _ = json.Marshal(Cache{Version: 1, QueriedAt: now, Records: []Record{
					{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Vulnerabilities: []ID{}},
				}})
			}

			deps := report.DependencyReport{Declarations: []report.Dependency{
				{ID: "known", Ecosystem: "npm", Module: "lodash", DeclaredVersion: "4.17.20", VersionSemantics: report.VersionExactLockfile},
				{ID: "outside-subset", Ecosystem: "npm", Module: "sample", DeclaredVersion: "1.2.3", VersionSemantics: report.VersionExactLockfile},
			}}
			got, err := Check(t.Context(), deps, o, now)
			if err != nil || len(got.Queries) != 2 || got.Queries[0].Status != tc.status {
				t.Fatalf("unexpected result: %+v, %v", got, err)
			}
			if tc.status == "bundled_match" {
				if got.Completeness != report.Partial || len(got.Matches) != 1 || got.Matches[0].Source.Revision != bundledRevision || got.Queries[1].Status == report.OutcomeCached {
					t.Fatalf("bundled evidence or coverage lost: %+v", got)
				}
				exported, err := Export(got)
				if err != nil || len(exported.Records) != 0 {
					t.Fatalf("bundled matches must not become complete cached answers: %+v, %v", exported, err)
				}
			} else if len(got.Matches) != 0 {
				t.Fatalf("bundled fallback overrode an exact answer: %+v", got.Matches)
			}
		})
	}
}

func TestBundledFallbackKeepsPartialOnlineEvidenceAndCachePrecedence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm"}],"next_page_token":"repeated"}]}`))
	}))
	defer server.Close()

	now := time.Now().UTC()
	deps := report.DependencyReport{Declarations: []report.Dependency{{
		ID: "known", Ecosystem: "npm", Module: "lodash", DeclaredVersion: "4.17.20", VersionSemantics: report.VersionExactLockfile,
	}}}
	o := DefaultOptions()
	o.Enabled, o.AllowNetwork, o.AllowLoopback, o.Endpoint = true, true, true, server.URL

	got, err := Check(t.Context(), deps, o, now)
	if err != nil || len(got.Queries) != 1 || got.Queries[0].Status != "pagination_loop" || got.Completeness != report.Partial ||
		len(got.Matches) != 1 || got.Matches[0].Source != (report.AdvisorySource{}) {
		t.Fatalf("bundled duplicate masked an incomplete online answer: %+v, %v", got, err)
	}

	o.Offline, err = json.Marshal(Cache{Version: 1, QueriedAt: now.Add(-time.Hour), Records: []Record{{
		Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Vulnerabilities: []ID{{ID: "GHSA-cached"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = Check(t.Context(), deps, o, now)
	if err != nil || len(got.Queries) != 1 || got.Queries[0].Status != report.OutcomeCached || got.Completeness != report.Complete ||
		len(got.Matches) != 2 || got.Matches[1].ID != "GHSA-cached" {
		t.Fatalf("fresh cache did not fill the pagination gap: %+v, %v", got, err)
	}
}
