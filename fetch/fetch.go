// Package fetch captures explicitly requested remote bytes. It never clones a
// repository, follows links inside an artifact, runs Git or starts package tools.
package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/skarm/scout/internal/netpolicy"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

// Options configures explicitly permitted remote acquisition. Defaults keep
// network access disabled.
type Options struct {
	// Enabled permits remote requests. DefaultOptions leaves it false.
	Enabled bool
	// AllowLoopback permits loopback destinations and plain HTTP to numeric
	// loopback addresses.
	AllowLoopback  bool
	Revision       string // GitHub repository input requires an explicit full commit SHA.
	ExpectedSHA256 string // Optional checksum of the downloaded bytes, not the snapshot.
	// MaxBytes limits the response body in bytes.
	MaxBytes int64
	// Timeout limits one HTTP request, including connection setup and response
	// reading.
	Timeout time.Duration
	RootCAs *x509.CertPool // Explicit trust from the API caller; never from an artifact.
}

// Provenance is the report representation of remote acquisition metadata.
type Provenance = report.SourceProvenance

// Payload contains downloaded bytes and the acquisition metadata associated
// with them.
type Payload struct {
	// Name is the safe capture label assigned to Data.
	Name string
	// Data contains the complete downloaded bytes after size and checksum
	// validation.
	Data []byte
	// Source records acquisition identity and checksum verification for Data.
	Source Provenance
}
type (
	// Target describes one resolved download request. Resolving it does not access
	// the network.
	// Part of the supported Go API for callers outside this repository.
	//goland:noinspection GoUnnecessarilyExportedIdentifiers
	Target struct {
		// URL is the resolved download address, including a pinned codeload URL for
		// GitHub inputs.
		URL string
		// Name is the safe capture filename assigned to the response.
		Name string
		// Kind identifies a direct HTTPS download or a GitHub repository archive.
		Kind string
		// Revision is the full commit SHA for a GitHub repository archive.
		Revision string
	}
	// Error contains a stable acquisition failure code without the raw target URL.
	Error struct {
		// Code is a stable machine-readable condition identifier.
		Code string
	}
)

// DefaultOptions returns bounded download settings with network permission
// disabled.
func DefaultOptions() Options { return Options{MaxBytes: 32 << 20, Timeout: 30 * time.Second} }

// IsRemote reports whether s contains a URL scheme separator. It does not
// validate the URL or authorize network access.
func IsRemote(s string) bool { return strings.Contains(s, "://") }

// ResolveTarget is pure: GitHub URLs are converted to a commit-pinned codeload
// request. Branch names, tags, marketplace pointers and subpaths are not guessed.
func ResolveTarget(raw string, o Options) (Target, error) {
	if err := o.Validate(); err != nil {
		return Target{}, err
	}

	if !o.Enabled {
		return Target{}, fail("network_permission_required")
	}

	u, err := parseURL(raw, o.AllowLoopback)
	if err != nil {
		return Target{}, err
	}

	t := Target{URL: u.String(), Name: "download.bin", Kind: "https"}
	if strings.EqualFold(u.Hostname(), "github.com") {
		return githubTarget(u, o.Revision)
	}

	if o.Revision != "" {
		return Target{}, fail("revision_only_for_github")
	}

	name := path.Base(u.Path)
	if safeName(name) {
		t.Name = name
	}

	return t, nil
}

// PermittedIP reports whether an address passes the download network policy.
// Loopback addresses require loopback to be true.
func PermittedIP(a netip.Addr, loopback bool) bool { return netpolicy.PermittedIP(a, loopback) }

// Get downloads an explicitly permitted target under ctx and validates its
// byte limit and optional checksum. Redirects are rejected.
func Get(ctx context.Context, raw string, o Options) (Payload, error) {
	var out Payload
	if ctx == nil {
		return out, fail("nil_context")
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}

	target, err := ResolveTarget(raw, o)
	if err != nil {
		return out, err
	}

	out.Name = target.Name
	out.Source = Provenance{
		Kind:              target.Kind,
		TargetSHA256:      hash([]byte(raw)),
		DownloadURLSHA256: hash([]byte(target.URL)),
		Revision:          target.Revision,
		Status:            report.OutcomeFailed,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return out, fail("invalid_request")
	}

	req.Header.Set("User-Agent", "scout-offline-first-mvp")
	req.Header.Set("Accept-Encoding", "identity")

	data, err := downloadData(ctx, req, o)
	if err != nil {
		return out, err
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}

	return out.capture(data, o)
}

// Validate checks download budgets, pin syntax and options that require
// network permission without making a request.
func (o Options) Validate() error {
	for _, budget := range []struct {
		value int64
		min   int64
		max   int64
		code  string
	}{
		{value: o.MaxBytes, min: 1, max: 128 << 20, code: "invalid_byte_budget"},
		{value: int64(o.Timeout), min: 1, max: int64(2 * time.Minute), code: "invalid_timeout"},
	} {
		if budget.value < budget.min || budget.value > budget.max {
			return fail(budget.code)
		}
	}

	for _, pin := range []struct {
		value  string
		length int
		code   string
	}{
		{value: o.Revision, length: 40, code: "revision_must_be_full_commit_sha"},
		{value: o.ExpectedSHA256, length: 64, code: "invalid_expected_checksum"},
	} {
		if pin.value != "" && !isHex(pin.value, pin.length) {
			return fail(pin.code)
		}
	}

	if !o.Enabled && o.requiresNetwork() {
		return fail("network_permission_required")
	}

	return nil
}

func (o Options) requiresNetwork() bool {
	return o.AllowLoopback || o.Revision != "" || o.ExpectedSHA256 != "" || o.RootCAs != nil
}

// Error returns a stable remote-input failure code without raw URL or network
// error text.
func (e *Error) Error() string { return "remote input: " + e.Code }

func (out Payload) capture(data []byte, o Options) (Payload, error) {
	if len(data) == 0 {
		return out, fail("empty_response")
	}

	digest := hash(data)
	if o.ExpectedSHA256 != "" && subtle.ConstantTimeCompare([]byte(digest), []byte(strings.ToLower(o.ExpectedSHA256))) != 1 {
		return out, fail("checksum_mismatch")
	}

	out.Data = data
	out.Source.BytesSHA256, out.Source.Bytes, out.Source.Status = digest, int64(len(data)), report.CaptureCaptured
	out.Source.ExpectedChecksumVerified = o.ExpectedSHA256 != ""

	return out, nil
}

func newClient(o Options) (*http.Client, *http.Transport) {
	transport := netpolicy.Transport(o.Timeout, o.AllowLoopback, o.RootCAs)
	client := &http.Client{
		Transport:     transport,
		Timeout:       o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return fail("redirect_refused") },
	}

	return client, transport
}

func fail(code string) error { return &Error{Code: code} }

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}

	_, err := hex.DecodeString(s)

	return err == nil
}

func hash(s []byte) string {
	h := sha256.Sum256(s)
	return hex.EncodeToString(h[:])
}

func repoPart(s string) bool { return s != "." && s != ".." && textmatch.Token(s, 128, "_.-") }

func safeName(s string) bool { return repoPart(s) && !strings.HasPrefix(s, ".") }

func parseURL(raw string, loopback bool) (*url.URL, error) {
	u, err := netpolicy.ParseURL(raw, netpolicy.URLPolicy{MaxBytes: 4096, AllowLoopback: loopback})
	if e, ok := errors.AsType[*netpolicy.Error](err); ok {
		return nil, fail(e.Code)
	}

	return u, err
}

func githubTarget(u *url.URL, revision string) (Target, error) {
	t := Target{}

	if u.Port() != "" && u.Port() != "443" {
		return Target{}, fail("invalid_github_url")
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return Target{}, fail("github_requires_repository_root")
	}

	parts[1] = strings.TrimSuffix(parts[1], ".git")
	for _, p := range parts {
		if !repoPart(p) {
			return Target{}, fail("invalid_github_url")
		}
	}

	if revision == "" {
		return Target{}, fail("github_requires_full_commit_sha")
	}

	t.Kind, t.Revision, t.Name = "github-archive", strings.ToLower(revision), "repository.zip"
	t.URL = "https://codeload.github.com/" + parts[0] + "/" + parts[1] + "/zip/" + t.Revision

	return t, nil
}
