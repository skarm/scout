//nolint:testpackage // Exercises private response parsing and cache limits.
package osv

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/scout/report"
)

func TestOSVPaginationDedupAndUnresolved(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Queries []struct {
				Version string `json:"version"`
				Page    string `json:"page_token"`
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
			t.Error(e)
		}
		if len(req.Queries) != 1 || req.Queries[0].Version != "1.2.3" || req.Queries[0].Package.Name != "sample" {
			t.Errorf("unexpected query %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			if _, err := w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-first"}],"next_page_token":"p2"}]}`)); err != nil {
				t.Error(err)
			}
		} else {
			if req.Queries[0].Page != "p2" {
				t.Error("missing page token")
			}
			if _, err := w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-second"}]}]}`)); err != nil {
				t.Error(err)
			}
		}
	}))
	defer server.Close()
	o := DefaultOptions()
	o.Enabled = true
	o.AllowNetwork = true
	o.AllowLoopback = true
	o.Endpoint = server.URL
	o.Timeout = time.Second
	r, e := Check(context.Background(), dependencies(), o, time.Now())
	if e != nil || calls != 2 || len(r.Matches) != 2 || len(r.Queries) != 3 || r.Completeness != report.Partial {
		t.Fatalf("%+v %v calls%d", r, e, calls)
	}
	for _, m := range r.Matches {
		if len(m.DependencyIDs) != 2 {
			t.Fatalf("occurrences lost %+v", m)
		}
	}
	if r.Queries[2].Status != "unresolved_version" {
		t.Fatal(r.Queries[2])
	}
}

func TestMalformedAndUnavailableAreNotClean(t *testing.T) {
	for _, body := range []string{`{"results":[]}`, `{"results":[{"vulns":null}]}`, `{"results":[{"vulns":[{"id":"bad\nsecret"}]}]}`, `{"results":[{}],"results":[{}]}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(body)); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			o := DefaultOptions()
			o.Enabled = true
			o.AllowNetwork = true
			o.AllowLoopback = true
			o.Endpoint = srv.URL
			deps := dependencies()
			deps.Declarations = deps.Declarations[:1]
			r, e := Check(context.Background(), deps, o, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			if r.Completeness == report.Complete || r.Queries[0].Status == "completed" {
				t.Fatalf("false clean %+v", r)
			}
		})
	}
}

func TestOfflineCacheFreshnessAndExactKey(t *testing.T) {
	now := time.Now().UTC()
	for _, age := range []time.Duration{time.Hour, 10 * 24 * time.Hour} {
		c := Cache{
			Version:   1,
			QueriedAt: now.Add(-age),
			Records: []Record{{
				Ecosystem:       "npm",
				Name:            "sample",
				Version:         "1.2.3",
				Vulnerabilities: []ID{{ID: "GHSA-test"}},
			}},
		}
		b, _ := json.Marshal(c)
		o := DefaultOptions()
		o.Enabled = true
		o.Offline = b
		r, e := Check(context.Background(), dependencies(), o, now)
		if e != nil {
			t.Fatal(e)
		}
		if (len(r.Matches) > 0) != (age < 7*24*time.Hour) {
			t.Fatalf("age%v %+v", age, r)
		}
	}
	o := DefaultOptions()
	o.Enabled = true
	if o.Validate() == nil {
		t.Fatal("implicit network")
	}
}

func TestPositiveFirstPageSurvivesPageFailure(t *testing.T) {
	n := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			if _, err := w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-retained"}],"next_page_token":"second"}]}`)); err != nil {
				t.Error(err)
			}
		} else {
			w.WriteHeader(503)
		}
	}))
	defer s.Close()
	o := DefaultOptions()
	o.Enabled = true
	o.AllowNetwork = true
	o.AllowLoopback = true
	o.Endpoint = s.URL
	d := dependencies()
	d.Declarations = d.Declarations[:1]
	r, e := Check(context.Background(), d, o, time.Now())
	if e != nil || len(r.Matches) != 1 || r.Completeness != report.Partial {
		t.Fatalf("%+v %v", r, e)
	}
}

func TestParsedManifestInventoryCanCompleteVulnerabilityCheck(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	cached := Cache{
		Version:   1,
		QueriedAt: now,
		Records: []Record{{
			Ecosystem:       "npm",
			Name:            "sample",
			Version:         "1.2.3",
			Vulnerabilities: []ID{},
		}},
	}
	raw, _ := json.Marshal(cached)
	o := DefaultOptions()
	o.Enabled = true
	o.Offline = raw
	deps := dependencies()
	deps.Declarations = deps.Declarations[:1]
	deps.Manifests[0].Status = "parsed_limited"
	r, err := Check(context.Background(), deps, o, now)
	if err != nil || r.Completeness != report.Complete || len(r.Queries) != 1 || r.Queries[0].Status != "cached" {
		t.Fatal(err, r)
	}
}

func TestExportPreservesCompletedCoordinatesAndFirstAdvisoryAssociation(t *testing.T) {
	analysis := report.VulnerabilityReport{QueriedAt: "2026-10-28T00:00:00Z", Queries: []report.VulnerabilityQuery{
		{DependencyID: "d1", Ecosystem: "npm", Name: "sample", Version: "1.2.3", Status: "completed"},
		{DependencyID: "d2", Ecosystem: "npm", Name: "sample", Version: "1.2.3", Status: "completed"},
		{DependencyID: "d3", Ecosystem: "PyPI", Name: "other", Version: "2", Status: "cached"},
		{DependencyID: "d4", Ecosystem: "PyPI", Name: "other", Version: "2", Status: "completed"},
	}, Matches: []report.Vulnerability{
		{ID: "GHSA-first", DependencyIDs: []string{"d1", "d1", "d2"}, DatabaseModified: "first"},
		{ID: "GHSA-first", DependencyIDs: []string{"d2"}, DatabaseModified: "later"},
		{ID: "GHSA-second", DependencyIDs: []string{"d2"}},
	}}
	got, err := Export(analysis)
	if err != nil || len(got.Records) != 2 {
		t.Fatal(got, err)
	}
	want := []ID{{ID: "GHSA-first", Modified: "first"}, {ID: "GHSA-second"}}
	if !reflect.DeepEqual(got.Records[0].Vulnerabilities, want) || got.Records[1].Vulnerabilities == nil || len(got.Records[1].Vulnerabilities) != 0 {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if parsed, err := ParseCache(raw); err != nil || !reflect.DeepEqual(parsed, got) {
		t.Fatal(parsed, err)
	}
	if _, err := Export(report.VulnerabilityReport{}); err == nil {
		t.Fatal("missing query time")
	}
	large := report.VulnerabilityReport{QueriedAt: analysis.QueriedAt}
	for i := range 2000 {
		large.Queries = append(large.Queries, report.VulnerabilityQuery{
			Status:    "completed",
			Ecosystem: "npm",
			Name:      strings.Repeat("n", 200) + strconv.Itoa(i),
			Version:   "1.2.3",
		})
	}
	if _, err := Export(large); err == nil {
		t.Fatal("oversize export")
	}
}

func TestCompletedCoordinateCacheRoundTripAtResultLimits(t *testing.T) {
	for _, count := range []int{1024, 1025, 4096, 4097} {
		for _, duplicate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/duplicate=%t", count, duplicate), func(t *testing.T) {
				r := paginatedResult(t, count, duplicate)
				wantStatus, wantCompleteness, wantMatches := "completed", report.Complete, count
				if count > 4096 {
					wantStatus, wantCompleteness, wantMatches = "result_limit", report.Partial, 4096
				} else if duplicate {
					wantMatches--
				}
				if r.Queries[0].Status != wantStatus || r.Completeness != wantCompleteness || len(r.Matches) != wantMatches {
					t.Fatalf("status=%s completeness=%s matches=%d; want %s %s %d", r.Queries[0].Status, r.Completeness, len(r.Matches), wantStatus, wantCompleteness, wantMatches)
				}
				cache, err := Export(r)
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(cache)
				if err != nil {
					t.Fatal(err)
				}
				imported, err := ParseCache(data)
				if err != nil {
					t.Fatalf("completed export cannot be imported: %v", err)
				}
				if count > 4096 {
					if len(imported.Records) != 0 {
						t.Fatal("partial results became a complete cached answer")
					}
				} else if len(imported.Records) != 1 || len(imported.Records[0].Vulnerabilities) != wantMatches {
					t.Fatalf("cache lost accepted matches: %+v", imported)
				}
			})
		}
	}
}

func TestCacheImportAndExportShareCoordinateResultCap(t *testing.T) {
	for _, count := range []int{1024, 1025, 4096, 4097} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			r := paginatedResult(t, min(count, 4096), false)
			if count > 4096 {
				r.Matches = append(r.Matches, report.Vulnerability{ID: "A-extra", DependencyIDs: []string{"d"}})
			}
			cache := Cache{
				Version:   1,
				QueriedAt: time.Now().UTC(),
				Records: []Record{{
					Ecosystem:       "npm",
					Name:            "sample",
					Version:         "1.2.3",
					Vulnerabilities: make([]ID, count),
				}},
			}
			for i := range cache.Records[0].Vulnerabilities {
				cache.Records[0].Vulnerabilities[i] = ID{ID: fmt.Sprintf("A-%d", i)}
			}
			data, _ := json.Marshal(cache)
			_, importErr := ParseCache(data)
			_, exportErr := Export(r)
			if (importErr != nil) != (count > 4096) || (exportErr != nil) != (count > 4096) {
				t.Fatalf("count=%d import=%v export=%v", count, importErr, exportErr)
			}
		})
	}
}

func TestCacheByteLimitStillAppliesToAcceptedCoordinateCount(t *testing.T) {
	r := paginatedResult(t, 4096, false)
	for i := range r.Matches {
		r.Matches[i].DatabaseModified = strings.Repeat("x", 128)
	}
	if _, err := Export(r); err == nil {
		t.Fatal("oversized cache export was accepted")
	}
	data, _ := json.Marshal(Cache{Version: 1, QueriedAt: time.Now().UTC(), Records: exportRecords(r)})
	if len(data) <= 256<<10 {
		t.Fatal("fixture did not exceed byte limit")
	}
	if _, err := ParseCache(data); err == nil {
		t.Fatal("oversized cache import was accepted")
	}
}

func TestDuplicateCachedIDsRetainRawCoordinateBudget(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		cache := Cache{
			Version:   1,
			QueriedAt: time.Now().UTC(),
			Records: []Record{{
				Ecosystem:       "npm",
				Name:            "sample",
				Version:         "1.2.3",
				Vulnerabilities: make([]ID, count),
			}},
		}
		for i := range cache.Records[0].Vulnerabilities {
			cache.Records[0].Vulnerabilities[i] = ID{ID: "A-repeated"}
		}
		data, _ := json.Marshal(cache)
		_, err := ParseCache(data)
		if (err != nil) != (count > 4096) {
			t.Fatalf("raw duplicate count=%d error=%v", count, err)
		}
		if err != nil {
			continue
		}
		o := DefaultOptions()
		o.Enabled, o.Offline = true, data
		deps := report.DependencyReport{Declarations: []report.Dependency{{
			ID:               "d",
			Ecosystem:        "npm",
			Module:           "sample",
			DeclaredVersion:  "1.2.3",
			VersionSemantics: "exact-lockfile",
		}}}
		r, err := Check(context.Background(), deps, o, cache.QueriedAt)
		if err != nil || r.Completeness != report.Complete || len(r.Matches) != 1 {
			t.Fatalf("cached duplicate IDs were not deduplicated: matches=%d error=%v", len(r.Matches), err)
		}
	}
}

func TestCacheFallbackSharesCoordinateResultBudgetAndRetainsPositiveEvidence(t *testing.T) {
	for _, cachedCount := range []int{4095, 4096} {
		t.Run(strconv.Itoa(cachedCount), func(t *testing.T) {
			now := time.Now().UTC()
			cache := Cache{
				Version:   1,
				QueriedAt: now,
				Records: []Record{{
					Ecosystem:       "npm",
					Name:            "sample",
					Version:         "1.2.3",
					Vulnerabilities: make([]ID, cachedCount),
				}},
			}
			for i := range cache.Records[0].Vulnerabilities {
				cache.Records[0].Vulnerabilities[i] = ID{ID: fmt.Sprintf("C-%d", i)}
			}
			data, _ := json.Marshal(cache)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"A-live-positive"}],"next_page_token":"next"}]}`))
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}))
			defer server.Close()
			o := DefaultOptions()
			o.Enabled, o.AllowNetwork, o.AllowLoopback, o.Endpoint, o.Offline = true, true, true, server.URL, data
			deps := report.DependencyReport{Declarations: []report.Dependency{{
				ID:               "d",
				Ecosystem:        "npm",
				Module:           "sample",
				DeclaredVersion:  "1.2.3",
				VersionSemantics: "exact-lockfile",
			}}}
			r, err := Check(context.Background(), deps, o, now)
			wantStatus, wantCompleteness := "cached", report.Complete
			if cachedCount == 4096 {
				wantStatus, wantCompleteness = "result_limit", report.Partial
			}
			if err != nil || calls.Load() != 2 || r.Completeness != wantCompleteness || r.Queries[0].Status != wantStatus || len(r.Matches) != 4096 {
				t.Fatalf("fallback exceeded or reset result budget: error=%v calls=%d completeness=%s status=%s matches=%d", err, calls.Load(), r.Completeness, r.Queries[0].Status, len(r.Matches))
			}
			if r.Matches[0].ID != "A-live-positive" {
				t.Fatal("previous positive evidence was discarded")
			}
		})
	}
}

func TestCacheValidationBoundaries(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	valid := Cache{
		Version:   1,
		QueriedAt: at,
		Records: []Record{{
			Ecosystem:       "npm",
			Name:            "sample",
			Version:         "1.2.3",
			Vulnerabilities: []ID{{ID: "GHSA-valid"}},
		}},
	}
	encode := func(c Cache) []byte {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := encode(valid)
	if got, err := ParseCache(raw); err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatal(got, err)
	}
	for _, alter := range []func(*Cache){
		func(c *Cache) { c.Version = 2 }, func(c *Cache) { c.QueriedAt = time.Time{} }, func(c *Cache) { c.Records = nil },
		func(c *Cache) { c.Records = append(c.Records, c.Records[0]) },
		func(c *Cache) { c.Records[0].Name = "" }, func(c *Cache) { c.Records[0].Version = "" },
		func(c *Cache) { c.Records[0].Ecosystem = "" }, func(c *Cache) { c.Records[0].Name = strings.Repeat("a", 257) },
		func(c *Cache) { c.Records[0].Version = strings.Repeat("a", 257) }, func(c *Cache) { c.Records[0].Vulnerabilities = nil },
		func(c *Cache) { c.Records[0].Vulnerabilities = []ID{{ID: "bad\nID"}} },
		func(c *Cache) { c.Records[0].Vulnerabilities = make([]ID, 1025) }, func(c *Cache) { c.Records = make([]Record, 4097) },
	} {
		c := valid
		c.Records = append([]Record(nil), valid.Records...)
		alter(&c)
		if _, err := ParseCache(encode(c)); err == nil {
			t.Fatalf("invalid cache admitted %+v", c)
		}
	}
	for _, text := range []string{`{`, `{"version":1,"version":1}`, `{"version":1,"queried_at":"2026-10-28T00:00:00Z","records":[],"unknown":1}`, strings.Repeat(" ", maxResponse+1)} {
		if _, err := ParseCache([]byte(text)); err == nil {
			t.Fatal("invalid cache admitted")
		}
	}
}

func TestCheckRejectsInvalidEnabledConfiguration(t *testing.T) {
	o := DefaultOptions()
	o.Enabled = true
	r, err := Check(context.Background(), report.DependencyReport{}, o, time.Now())
	if err == nil || !r.Enabled || len(r.Queries) != 0 || len(r.Matches) != 0 {
		t.Fatalf("invalid enabled configuration became an observation: error=%v report=%+v", err, r)
	}
}

func TestCheckRejectsNilContextBeforeQuerying(t *testing.T) {
	o := DefaultOptions()
	o.Enabled, o.AllowNetwork = true, true
	r, err := Check(nil, report.DependencyReport{}, o, time.Now())
	if err == nil || !r.Enabled || len(r.Queries) != 0 || len(r.Matches) != 0 {
		t.Fatalf("nil context became an observation: error=%v report=%+v", err, r)
	}
}

func TestCachedExactAnswerDoesNotCompleteAnIncompleteManifestInventory(t *testing.T) {
	now := time.Now().UTC()
	data, err := json.Marshal(Cache{
		Version:   1,
		QueriedAt: now,
		Records: []Record{{
			Ecosystem:       "npm",
			Name:            "sample",
			Version:         "1.2.3",
			Vulnerabilities: []ID{},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions()
	o.Enabled, o.Offline = true, data
	deps := report.DependencyReport{
		Manifests: []report.DependencyManifest{{Path: "package-lock.json", Status: "parse_error"}},
		Declarations: []report.Dependency{{
			ID:               "d",
			Ecosystem:        "npm",
			Module:           "sample",
			DeclaredVersion:  "1.2.3",
			VersionSemantics: "exact-lockfile",
		}},
	}
	r, err := Check(context.Background(), deps, o, now)
	if err != nil || r.Completeness != report.Partial || len(r.Queries) != 1 || r.Queries[0].Status != "cached" || len(r.Matches) != 0 {
		t.Fatalf("exact cached answer erased incomplete manifest scope: error=%v report=%+v", err, r)
	}
}

func TestVulnerabilityOptionLimitsAndMode(t *testing.T) {
	for _, alter := range []func(*Options){
		func(o *Options) { o.Timeout = 0 }, func(o *Options) { o.Timeout = 2*time.Minute + 1 },
		func(o *Options) { o.MaxQueries = 0 }, func(o *Options) { o.MaxQueries = 8193 },
		func(o *Options) { o.MaxRequests = 0 }, func(o *Options) { o.MaxRequests = 257 },
		func(o *Options) { o.MaxCacheAge = time.Minute - 1 }, func(o *Options) { o.MaxCacheAge = 366 * 24 * time.Hour },
		func(o *Options) { o.AllowNetwork = true }, func(o *Options) { o.AllowLoopback = true }, func(o *Options) { o.RootCAs = x509.NewCertPool() },
		func(o *Options) { o.Offline = []byte(`{}`) }, func(o *Options) { o.Enabled = true },
		func(o *Options) { o.Enabled = true; o.AllowNetwork = true; o.Endpoint = "file:///tmp/cache" },
		func(o *Options) { o.Enabled = true; o.Offline = []byte(strings.Repeat("x", maxResponse+1)) },
		func(o *Options) { o.Enabled = true; o.Offline = []byte(`{}`) },
	} {
		o := DefaultOptions()
		alter(&o)
		if err := o.Validate(); err == nil {
			t.Fatalf("invalid options admitted %+v", o)
		}
	}
	if err := DefaultOptions().Validate(); err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions()
	o.Enabled = true
	o.AllowNetwork = true
	if _, err := Check(nil, report.DependencyReport{}, o, time.Now()); err == nil {
		t.Fatal("nil context")
	}
}

func TestResponseShapeAndContentGrammar(t *testing.T) {
	for _, tc := range []struct {
		text  string
		valid bool
	}{
		{text: `{"results":[{}]}`, valid: true},
		{text: `{"results":[{"vulns":[],"next_page_token":"next"}]}`, valid: true},
		{text: `{"results":[{"vulns":[{"id":"GHSA-valid","modified":"today"}]}]}`, valid: true},
		{text: `null`, valid: false},
		{text: `{"results":null}`, valid: false},
		{text: `{"results":[]}`, valid: false},
		{text: `{"results":[null]}`, valid: false},
		{text: `{"results":[{"error":null}]}`, valid: false},
		{text: `{"results":[{"next_page_token":1}]}`, valid: false},
		{text: `{"results":[{"vulns":{}}]}`, valid: false},
		{text: `{"results":[{"vulns":[null]}]}`, valid: false},
		{text: `{"results":[{"vulns":[{}]}]}`, valid: false},
		{text: `{"results":[{"vulns":[{"id":"bad\nID"}]}]}`, valid: false},
		{text: `{"results":[{"vulns":[{"id":"GHSA-valid","modified":false}]}]}`, valid: false},
		{text: fmt.Sprintf(`{"results":[{"next_page_token":%q}]}`, strings.Repeat("t", 4097)), valid: false},
		{
			text:  fmt.Sprintf(`{"results":[{"vulns":[{"id":"GHSA-valid","modified":%q}]}]}`, strings.Repeat("t", 129)),
			valid: false,
		},
	} {
		if _, valid := decodeQueryResponse(context.Background(), []byte(tc.text), 1); valid != tc.valid {
			t.Fatalf("%s valid=%v", tc.text, valid)
		}
	}
}

func dependencies() report.DependencyReport {
	return report.DependencyReport{
		Manifests: []report.DependencyManifest{{
			Path:   "package-lock.json",
			Status: "completed",
		}},
		Declarations: []report.Dependency{{
			ID:               "d1",
			Ecosystem:        "npm",
			Module:           "sample",
			DeclaredVersion:  "1.2.3",
			VersionSemantics: "exact-lockfile",
		}, {
			ID:               "d2",
			Ecosystem:        "npm",
			Module:           "sample",
			DeclaredVersion:  "1.2.3",
			VersionSemantics: "exact-lockfile",
		}, {
			ID:               "d3",
			Ecosystem:        "npm",
			Module:           "other",
			DeclaredVersion:  "unresolved",
			VersionSemantics: "unresolved",
		}},
	}
}

// Feed valid provider pages through the same decode/accumulate/publish path as
// queryBatch, without requiring a listening socket or executing artifact code.
func paginatedResult(t *testing.T, count int, duplicate bool) report.VulnerabilityReport {
	t.Helper()
	r := report.VulnerabilityReport{
		Completeness: report.Complete,
		QueriedAt:    time.Now().UTC().Format(time.RFC3339),
		Queries: []report.VulnerabilityQuery{{
			DependencyID: "d",
			Ecosystem:    "npm",
			Name:         "sample",
			Version:      "1.2.3",
			Status:       "pending",
		}},
	}
	g := &queryGroup{indices: []int{0}, tokens: map[string]bool{}}
	set := func(g *queryGroup, status string) { setQueryStatus(g, status, &r) }
	for start := 0; start < count; start += 1024 {
		end := min(start+1024, count)
		ids := make([]ID, 0, end-start)
		for i := start; i < end; i++ {
			id := i
			if duplicate && i == count-1 {
				id = 0
			}
			ids = append(ids, ID{ID: fmt.Sprintf("A-%d", id)})
		}
		next := ""
		if end < count {
			next = strconv.Itoa(end)
		}
		body, _ := json.Marshal(map[string]any{"results": []any{map[string]any{"vulns": ids, "next_page_token": next}}})
		out, valid := decodeQueryResponse(context.Background(), body, 1)
		if !valid {
			t.Fatal("valid provider page was rejected")
		}
		applyQueryResponse(out, []*queryGroup{g}, set)
	}
	collectMatches([]*queryGroup{g}, &r)
	return r
}
