// Package osv performs bounded, opt-in OSV queries for exact captured
// coordinates. It never installs packages or treats a range as a selected version.
package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const (
	maxResponse          = 256 << 10
	maxCoordinateResults = 4096
	maxPageResults       = 1024
	maxCacheRecords      = 4096
)

// Options configures explicit offline-cache or network advisory lookup.
// Defaults keep lookup disabled.
type Options struct {
	// RootCAs supplies an optional caller-trusted CA pool for advisory requests.
	RootCAs *x509.CertPool
	// Endpoint is the explicit operator-selected service URL. It is never read
	// from inspected content.
	Endpoint string
	// Offline is an explicitly supplied, exact-query cache, not a complete CVE DB.
	Offline []byte
	// Timeout bounds a network advisory request.
	Timeout time.Duration
	// MaxQueries bounds distinct exact-coordinate advisory queries.
	MaxQueries int
	// MaxRequests limits network requests, including pagination and failed attempts.
	MaxRequests int
	// MaxCacheAge bounds the age of an explicitly supplied advisory cache.
	MaxCacheAge time.Duration
	// Enabled selects advisory lookup; false performs no queries.
	Enabled bool
	// AllowNetwork permits advisory requests independently of enabling advisory lookup.
	AllowNetwork bool
	// AllowLoopback permits explicit loopback endpoints; private non-loopback
	// destinations remain subject to network policy.
	AllowLoopback bool
}

// Record stores advisory IDs returned for one exact ecosystem, package name
// and version.
type Record struct {
	// Ecosystem identifies the package ecosystem used for exact-coordinate
	// advisory lookup.
	Ecosystem string `json:"ecosystem"`
	// Name is the exact package name used in the cached advisory query.
	Name string `json:"name"`
	// Version is the exact package version used in the cached query.
	Version string `json:"version"`
	// Vulnerabilities lists advisory identities returned for these exact package
	// coordinates.
	Vulnerabilities []ID `json:"vulnerabilities"`
}

// Cache is a versioned set of exact advisory query results with one query
// timestamp.
type Cache struct {
	// Version is the exact-query cache schema version; the supported value is 1.
	Version int `json:"version"`
	// QueriedAt is the supplied trusted query time used to assess cache age.
	QueriedAt time.Time `json:"queried_at"`
	// Records contains the exact-coordinate results stored in this cache.
	Records []Record `json:"records"`
}

// ID records an advisory identity and its database modification timestamp.
type ID struct {
	// ID is the advisory identity reported by the database.
	ID string `json:"id"`
	// Modified retains the advisory modification timestamp reported by the database.
	Modified string `json:"modified,omitempty"`
}

type query struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Token string `json:"page_token,omitempty"`
}

type response struct {
	Results []struct {
		Vulns []ID   `json:"vulns"`
		Next  string `json:"next_page_token"`
	} `json:"results"`
}

type queryGroup struct {
	q       query
	indices []int
	ids     []ID
	done    bool
	tokens  map[string]bool
}

type queryPayload struct {
	Queries []query `json:"queries"`
}

// DefaultOptions returns bounded advisory lookup settings with network access
// and lookup disabled.
func DefaultOptions() Options {
	return Options{
		Endpoint:    "https://api.osv.dev/v1/querybatch",
		Timeout:     20 * time.Second,
		MaxQueries:  4096,
		MaxRequests: 128,
		MaxCacheAge: 7 * 24 * time.Hour,
	}
}

// ParseCache decodes a bounded versioned exact-query cache, rejecting
// ambiguous JSON and invalid coordinates.
func ParseCache(data []byte) (Cache, error) {
	var c Cache
	if len(data) > maxResponse {
		return c, errors.New("cache too large")
	}

	// The byte bound also bounds the number of JSON nodes. A cache can contain
	// more nodes than one provider page while retaining identical strict parsing.
	shape, err := jsonconfig.ParseWithNodeLimit(context.Background(), string(data), len(data))
	if err != nil || cacheAliases(shape) {
		return c, errors.New("invalid cache JSON")
	}

	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()

	if d.Decode(&c) != nil || c.Version != 1 || c.QueriedAt.IsZero() || c.Records == nil {
		return c, errors.New("invalid cache schema")
	}

	if err := validateCacheRecords(c.Records); err != nil {
		return c, err
	}

	return c, nil
}

// Check preserves every selected dependency and every query outcome in its report.
// Incomplete pages never become a clean answer; prior positive matches survive.
func Check(ctx context.Context, deps report.DependencyReport, o Options, now time.Time) (report.VulnerabilityReport, error) {
	r := report.VulnerabilityReport{
		Enabled:      o.Enabled,
		Source:       "disabled",
		Completeness: report.Complete,
		Queries:      []report.VulnerabilityQuery{},
		Matches:      []report.Vulnerability{},
		Limitations:  []string{"Exact captured coordinates only; not dependency reachability, integrity, full install closure or proof that a package is installed.", "No built-in complete offline CVE database. A supplied cache covers only its exact records and age."},
	}
	if err := o.Validate(); err != nil {
		return r, err
	}

	if !o.Enabled {
		return r, nil
	}

	if ctx == nil {
		return r, errors.New("nil context")
	}

	r.Source = "OSV-querybatch"
	r.QueriedAt = now.UTC().Format(time.RFC3339)
	cached, cachedAt := prepareCache(o, now, &r)

	for _, m := range deps.Manifests {
		if !m.InventoryComplete() {
			r.Completeness = report.Partial
		}
	}

	groups := groupQueries(deps, o, &r)
	set := func(g *queryGroup, status string) { setQueryStatus(g, status, &r) }
	fallback := func(g *queryGroup, status string) {
		if x, ok := cached[key(g.q.Package.Ecosystem, g.q.Package.Name, g.q.Version)]; ok {
			// A report and its exported cache have one timestamp. Use the oldest
			// included source so a network fallback cannot renew cached answers.
			r.QueriedAt = cachedAt.UTC().Format(time.RFC3339)

			if !g.appendResults(x.Vulnerabilities) {
				set(g, "result_limit")
				return
			}

			set(g, report.OutcomeCached)
		} else {
			set(g, status)
		}
	}

	requests := 0
	for start := 0; start < len(groups); start += 64 {
		queryBatch(ctx, groups[start:min(start+64, len(groups))], o, &requests, set, fallback)
	}

	collectMatches(groups, &r)

	return r, nil
}

// Export builds a validated exact-query cache from completed or cached report
// queries using the oldest included query time. It does not encode JSON or
// renew cached answers.
func Export(r report.VulnerabilityReport) (Cache, error) {
	at, err := time.Parse(time.RFC3339, r.QueriedAt)
	if err != nil {
		return Cache{}, errors.New("report has no query time")
	}

	c := Cache{Version: 1, QueriedAt: at, Records: []Record{}}

	c.Records = exportRecords(r)
	if err := validateCacheRecords(c.Records); err != nil {
		return Cache{}, err
	}

	b, err := json.Marshal(c)
	if err != nil {
		return Cache{}, err
	}

	if len(b) > maxResponse {
		return Cache{}, errors.New("export exceeds cache limit")
	}

	return c, nil
}

// Validate checks lookup budgets, endpoint policy and explicit cache or
// network configuration without querying a service.
func (o Options) Validate() error {
	if err := o.validateLimits(); err != nil {
		return err
	}

	if err := o.validateMode(); err != nil {
		return err
	}

	if o.AllowNetwork {
		fo := fetch.DefaultOptions()
		fo.Enabled = true

		fo.AllowLoopback = o.AllowLoopback
		if _, err := fetch.ResolveTarget(o.Endpoint, fo); err != nil {
			return errors.New("invalid OSV endpoint")
		}
	}

	if len(o.Offline) > maxResponse {
		return errors.New("offline vulnerability cache limit")
	}

	if len(o.Offline) > 0 {
		if _, err := ParseCache(o.Offline); err != nil {
			return err
		}
	}

	return nil
}

func (o Options) validateLimits() error {
	for _, bound := range []struct{ value, minimum, maximum int64 }{
		{value: int64(o.Timeout), minimum: 1, maximum: int64(2 * time.Minute)}, {
			value:   int64(o.MaxQueries),
			minimum: 1,
			maximum: 8192,
		}, {
			value:   int64(o.MaxRequests),
			minimum: 1,
			maximum: 256,
		}, {
			value:   int64(o.MaxCacheAge),
			minimum: int64(time.Minute),
			maximum: int64(365 * 24 * time.Hour),
		},
	} {
		if bound.value < bound.minimum || bound.value > bound.maximum {
			return errors.New("invalid vulnerability limits")
		}
	}

	return nil
}

func (o Options) validateMode() error {
	if !o.Enabled && (o.AllowNetwork || o.AllowLoopback || len(o.Offline) > 0 || o.RootCAs != nil) {
		return errors.New("vulnerability options require enabling checks")
	}

	if o.Enabled && !o.AllowNetwork && len(o.Offline) == 0 {
		return errors.New("vulnerability checks require explicit network permission or offline cache")
	}

	return nil
}

// Online pages and cache fallback spend the same coordinate inventory. Keep
// earlier positive evidence and admit only the remaining bounded prefix.
func (g *queryGroup) appendResults(values []ID) bool {
	n := min(len(values), maxCoordinateResults-len(g.ids))
	g.ids = append(g.ids, values[:n]...)

	return n == len(values)
}

func safeID(s string) bool { return textmatch.Token(s, 160, "._:-") && textmatch.Alnum(s[0]) }

func validateCacheRecords(records []Record) error {
	if len(records) > maxCacheRecords {
		return errors.New("cache record limit")
	}

	seen := map[string]bool{}

	for _, r := range records {
		if !cacheRecordValid(r) {
			return errors.New("invalid cache record")
		}

		k := key(r.Ecosystem, r.Name, r.Version)
		if seen[k] {
			return errors.New("duplicate cache record")
		}

		seen[k] = true

		for _, v := range r.Vulnerabilities {
			if !safeID(v.ID) {
				return errors.New("invalid vulnerability id")
			}
		}
	}

	return nil
}

func cacheRecordValid(r Record) bool {
	return r.Ecosystem != "" && r.Name != "" && r.Version != "" && len(r.Name) <= 256 && len(r.Version) <= 256 && r.Vulnerabilities != nil && len(r.Vulnerabilities) <= maxCoordinateResults
}

func prepareCache(o Options, now time.Time, r *report.VulnerabilityReport) (map[string]Record, time.Time) {
	cached := map[string]Record{}

	var queriedAt time.Time

	if len(o.Offline) > 0 {
		c, _ := ParseCache(o.Offline)
		age := now.Sub(c.QueriedAt)

		if age >= 0 && age <= o.MaxCacheAge {
			queriedAt = c.QueriedAt
			for _, x := range c.Records {
				cached[key(x.Ecosystem, x.Name, x.Version)] = x
			}
		}

		h := sha256.Sum256(o.Offline)

		r.DatabaseSHA256 = hex.EncodeToString(h[:])
		if !o.AllowNetwork {
			r.Source = "operator-exact-query-cache"
			r.QueriedAt = c.QueriedAt.Format(time.RFC3339)
		}
	}

	return cached, queriedAt
}

func groupQueries(deps report.DependencyReport, o Options, r *report.VulnerabilityReport) []*queryGroup {
	groups := make([]*queryGroup, 0)
	byKey := map[string]*queryGroup{}

	for _, d := range deps.Declarations {
		qi := len(r.Queries)
		q := report.VulnerabilityQuery{
			DependencyID: d.ID,
			Ecosystem:    d.Ecosystem,
			Name:         d.Module,
			Version:      d.DeclaredVersion,
			Status:       "pending",
		}

		exact := d.VersionSemantics == report.VersionExactLockfile || d.VersionSemantics == report.VersionExactDeclaration
		if !exact {
			q.Status = "unresolved_version"
			r.Completeness = report.Partial
			r.Queries = append(r.Queries, q)

			continue
		}

		k := key(d.Ecosystem, d.Module, d.DeclaredVersion)
		g := byKey[k]

		if g == nil && len(groups) >= o.MaxQueries {
			q.Status = "query_limit"
			r.Completeness = report.Partial
			r.Queries = append(r.Queries, q)

			continue
		}

		r.Queries = append(r.Queries, q)

		if g == nil {
			g = &queryGroup{tokens: map[string]bool{}}
			g.q.Package.Name = d.Module
			g.q.Package.Ecosystem = d.Ecosystem
			g.q.Version = d.DeclaredVersion
			byKey[k] = g
			groups = append(groups, g)
		}

		g.indices = append(g.indices, qi)
	}

	return groups
}

func setQueryStatus(g *queryGroup, status string, r *report.VulnerabilityReport) {
	for _, i := range g.indices {
		r.Queries[i].Status = status
	}

	g.done = true

	if status != report.OutcomeCompleted && status != report.OutcomeCached {
		r.Completeness = report.Partial
	}
}

func queryBatch(ctx context.Context, batch []*queryGroup, o Options, requests *int, set, fallback func(*queryGroup, string)) {
	for {
		pending, payload := pendingQueries(batch)

		if len(pending) == 0 {
			break
		}

		if !o.AllowNetwork {
			setPending(pending, "not_cached", fallback)

			break
		}

		if ctx.Err() != nil {
			setPending(pending, "cancelled", set)

			break
		}

		if *requests >= o.MaxRequests {
			setPending(pending, "request_limit", fallback)

			break
		}

		data, _ := json.Marshal(payload)
		*requests++
		fo := fetch.DefaultOptions()
		fo.Enabled = true
		fo.AllowLoopback = o.AllowLoopback
		fo.Timeout = o.Timeout
		fo.MaxBytes = maxResponse
		fo.RootCAs = o.RootCAs

		body, err := fetch.PostJSON(ctx, o.Endpoint, data, fo)
		if err != nil {
			setPending(pending, "provider_failed", fallback)

			continue
		}

		out, valid := decodeQueryResponse(ctx, body, len(pending))
		if !valid {
			setPending(pending, "invalid_response", set)

			continue
		}

		applyQueryResponse(out, pending, set)
	}
}

func pendingQueries(batch []*queryGroup) ([]*queryGroup, queryPayload) {
	pending := make([]*queryGroup, 0)
	payload := queryPayload{Queries: []query{}}

	for _, g := range batch {
		if !g.done {
			pending = append(pending, g)
			payload.Queries = append(payload.Queries, g.q)
		}
	}

	return pending, payload
}

func setPending(groups []*queryGroup, status string, set func(*queryGroup, string)) {
	for _, g := range groups {
		set(g, status)
	}
}

func decodeQueryResponse(ctx context.Context, body []byte, count int) (response, bool) {
	shape, err := jsonconfig.Parse(ctx, string(body))
	if err != nil || validateResponseShape(shape, count) != nil {
		return response{}, false
	}

	var out response
	if err := json.Unmarshal(body, &out); err != nil || out.Results == nil || len(out.Results) != count {
		return response{}, false
	}

	return out, validQueryResults(out)
}

func validQueryResults(out response) bool {
	valid := true

	for _, res := range out.Results {
		if len(res.Next) > 4096 || len(res.Vulns) > maxPageResults {
			valid = false
		}

		for _, v := range res.Vulns {
			if !safeID(v.ID) || len(v.Modified) > 128 {
				valid = false
			}
		}
	}

	return valid
}

func applyQueryResponse(out response, pending []*queryGroup, set func(*queryGroup, string)) {
	for i, g := range pending {
		res := out.Results[i]

		if !g.appendResults(res.Vulns) {
			set(g, "result_limit")

			continue
		}

		if res.Next == "" {
			set(g, report.OutcomeCompleted)
		} else if g.tokens[res.Next] {
			set(g, "pagination_loop")
		} else {
			g.tokens[res.Next] = true
			g.q.Token = res.Next
		}
	}
}

func collectMatches(groups []*queryGroup, r *report.VulnerabilityReport) {
	for _, g := range groups {
		seen := map[string]bool{}
		for _, v := range g.ids {
			if seen[v.ID] {
				continue
			}

			seen[v.ID] = true

			ids := make([]string, 0, len(g.indices))
			for _, i := range g.indices {
				ids = append(ids, r.Queries[i].DependencyID)
			}

			r.Matches = append(r.Matches, report.Vulnerability{
				ID:               v.ID,
				DependencyIDs:    ids,
				DatabaseModified: v.Modified,
			})
		}
	}

	sort.Slice(r.Matches, func(i, j int) bool {
		if r.Matches[i].ID != r.Matches[j].ID {
			return r.Matches[i].ID < r.Matches[j].ID
		}

		return r.Matches[i].DependencyIDs[0] < r.Matches[j].DependencyIDs[0]
	})
}

func exportRecords(r report.VulnerabilityReport) []Record {
	byDependency := map[string][]ID{}

	for _, match := range r.Matches {
		for _, dep := range match.DependencyIDs {
			byDependency[dep] = append(byDependency[dep], ID{ID: match.ID, Modified: match.DatabaseModified})
		}
	}

	records := make([]Record, 0)
	positions := map[string]int{}
	seen := map[int]map[string]bool{}

	for _, q := range r.Queries {
		if q.Status != report.OutcomeCompleted && q.Status != report.OutcomeCached {
			continue
		}

		coordinate := key(q.Ecosystem, q.Name, q.Version)

		at, exists := positions[coordinate]
		if !exists {
			at = len(records)
			positions[coordinate] = at

			records = append(records, Record{
				Ecosystem:       q.Ecosystem,
				Name:            q.Name,
				Version:         q.Version,
				Vulnerabilities: []ID{},
			})
			seen[at] = map[string]bool{}
		}

		for _, v := range byDependency[q.DependencyID] {
			if seen[at][v.ID] {
				continue
			}

			records[at].Vulnerabilities = append(records[at].Vulnerabilities, v)
			seen[at][v.ID] = true
		}
	}

	return records
}

func key(e, n, v string) string { return e + "\x00" + n + "\x00" + v }

func validateResponseShape(root *jsonconfig.Node, count int) error {
	if root == nil || root.Kind != jsonconfig.KindObject || fieldAliases(root, "results") {
		return errors.New("invalid response")
	}

	results := root.Get("results")
	if results == nil || results.Kind != jsonconfig.KindArray || len(results.Elements) != count {
		return errors.New("invalid results")
	}

	for _, item := range results.Elements {
		if err := validateResultShape(item); err != nil {
			return err
		}
	}

	return nil
}

func validateResultShape(item *jsonconfig.Node) error {
	if item == nil || item.Kind != jsonconfig.KindObject || item.Get("error") != nil || fieldAliases(item, "vulns", "next_page_token", "error") {
		return errors.New("invalid result")
	}

	if n := item.Get("next_page_token"); n != nil && n.Kind != jsonconfig.KindString {
		return errors.New("invalid token")
	}

	return validateVulnerabilityShapes(item.Get("vulns"))
}

func validateVulnerabilityShapes(n *jsonconfig.Node) error {
	if n != nil {
		if n.Kind != jsonconfig.KindArray {
			return errors.New("invalid vulnerabilities")
		}

		for _, v := range n.Elements {
			if err := validateVulnerabilityShape(v); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateVulnerabilityShape(v *jsonconfig.Node) error {
	if v.Kind != jsonconfig.KindObject || fieldAliases(v, "id", "modified") {
		return errors.New("invalid vulnerability")
	}

	id, ok := v.Get("id").Text()
	if !ok || !safeID(id) {
		return errors.New("invalid vulnerability id")
	}

	if m := v.Get("modified"); m != nil && m.Kind != jsonconfig.KindString {
		return errors.New("invalid timestamp")
	}

	return nil
}

// encoding/json folds struct field names. Reject aliases before decoding so
// validation and the consumed advisory/cache values cannot disagree.
func fieldAliases(n *jsonconfig.Node, fields ...string) bool {
	if n == nil {
		return false
	}

	for _, member := range n.Members {
		for _, field := range fields {
			if member.Key != field && strings.EqualFold(member.Key, field) {
				return true
			}
		}
	}

	return false
}

func cacheAliases(root *jsonconfig.Node) bool {
	if fieldAliases(root, "version", "queried_at", "records") {
		return true
	}

	if records := root.Get("records"); records != nil {
		for _, record := range records.Elements {
			if fieldAliases(record, "ecosystem", "name", "version", "vulnerabilities") {
				return true
			}

			if vulnerabilities := record.Get("vulnerabilities"); vulnerabilities != nil {
				for _, vulnerability := range vulnerabilities.Elements {
					if fieldAliases(vulnerability, "id", "modified") {
						return true
					}
				}
			}
		}
	}

	return false
}
