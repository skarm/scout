package fetch_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/scout/fetch"
)

func TestResolveAndValidation(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct{ name, url, rev, want string }{
		{name: "pinned", url: "https://github.com/owner/repository", rev: sha, want: ""},
		{name: "git-suffix", url: "https://github.com/owner/repository.git", rev: sha, want: ""},
		{
			name: "mutable-ref",
			url:  "https://github.com/owner/repository",
			rev:  "main",
			want: "revision_must_be_full_commit_sha",
		},
		{
			name: "unspecified-ref",
			url:  "https://github.com/owner/repository",
			rev:  "",
			want: "github_requires_full_commit_sha",
		},
		{
			name: "tree-not-guessed",
			url:  "https://github.com/owner/repository/tree/" + sha,
			rev:  sha,
			want: "github_requires_repository_root",
		},
		{name: "private", url: "https://169.254.169.254/latest/meta-data/", rev: "", want: "address_not_permitted"},
		{name: "creds", url: "https://SENTINEL:x@example.com/a", rev: "", want: "invalid_url"},
		{name: "query", url: "https://example.com/a?token=SENTINEL", rev: "", want: "invalid_url"},
		{name: "http", url: "http://example.com/a", rev: "", want: "https_required"},
		{name: "percent-slash", url: "https://example.com/a%2fb", rev: "", want: "invalid_url"},
		{name: "ftp", url: "ftp://example.com/a", rev: "", want: "https_required"},
		{name: "bad-port", url: "https://example.com:999999999/a", rev: "", want: "invalid_port"},
		{name: "direct", url: "https://example.com/SKILL.md", rev: "", want: ""},
		{name: "ref-on-direct", url: "https://example.com/a", rev: sha, want: "revision_only_for_github"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := enabled()
			o.Revision = tc.rev
			target, err := fetch.ResolveTarget(tc.url, o)
			if code(err) != tc.want {
				t.Fatalf("got %s want %s", code(err), tc.want)
			}
			if strings.Contains(fmt.Sprint(err), "SENTINEL") {
				t.Fatal("input leaked")
			}
			if tc.name == "pinned" && (target.URL != "https://codeload.github.com/owner/repository/zip/"+sha || target.Name != "repository.zip") {
				t.Fatal(target)
			}
		})
	}
	if _, err := fetch.ResolveTarget("https://example.com/SKILL.md", fetch.DefaultOptions()); code(err) != "network_permission_required" {
		t.Fatal(err)
	}
}

func TestAddressPolicy(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "192.0.2.1", "198.18.0.1", "224.0.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2001:db8::1", "2002:a00:1::1", "3fff::1"} {
		if fetch.PermittedIP(netip.MustParseAddr(ip), false) {
			t.Errorf("allowed %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !fetch.PermittedIP(netip.MustParseAddr(ip), false) {
			t.Errorf("denied public address %s", ip)
		}
	}
	if !fetch.PermittedIP(netip.MustParseAddr("::1"), true) || fetch.PermittedIP(netip.MustParseAddr("10.0.0.1"), true) {
		t.Fatal("loopback permission broadened")
	}
}

func TestCaptureAndChecksum(t *testing.T) {
	var requests atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("ambient credentials")
		}
		w.Header().Set("Content-Disposition", `attachment; filename="../../escape"`)
		if _, err := fmt.Fprint(w, "test payload"); err != nil {
			t.Error(err)
		}
	}))
	defer s.Close()
	o := enabled()
	h := sha256.Sum256([]byte("test payload"))
	o.ExpectedSHA256 = hex.EncodeToString(h[:])
	got, err := fetch.Get(context.Background(), s.URL+"/SKILL.md", o)
	if err != nil || string(got.Data) != "test payload" || got.Name != "SKILL.md" || !got.Source.ExpectedChecksumVerified || got.Source.BytesSHA256 != o.ExpectedSHA256 {
		t.Fatalf("%+v %v", got, err)
	}
	o.ExpectedSHA256 = strings.Repeat("0", 64)
	got, err = fetch.Get(context.Background(), s.URL+"/SKILL.md", o)
	if code(err) != "checksum_mismatch" || len(got.Data) != 0 || got.Source.Status != "failed" {
		t.Fatal(got, err)
	}
	o = fetch.DefaultOptions()
	_, err = fetch.Get(context.Background(), s.URL, o)
	if code(err) != "network_permission_required" || requests.Load() != 2 {
		t.Fatal("network request without permission")
	}
}

func TestHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		serve      func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "limit",
			want: "byte_limit",
			serve: func(w http.ResponseWriter, r *http.Request) {
				if _, err := fmt.Fprint(w, strings.Repeat("x", 2048)); err != nil {
					t.Error(err)
				}
			},
		},
		{name: "stream-limit", want: "byte_limit", serve: func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			if _, err := fmt.Fprint(w, strings.Repeat("x", 2048)); err != nil {
				t.Error(err)
			}
		}},
		{name: "encoding", want: "content_encoding_refused", serve: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			if _, err := fmt.Fprint(w, "x"); err != nil {
				t.Error(err)
			}
		}},
		{
			name: "status",
			want: "http_status",
			serve: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(401)
				if _, err := fmt.Fprint(w, "SENTINEL"); err != nil {
					t.Error(err)
				}
			},
		},
		{name: "empty", want: "empty_response", serve: func(w http.ResponseWriter, r *http.Request) {}},
		{name: "redirect", want: "redirect_refused", serve: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/secret", http.StatusFound)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(tc.serve))
			defer s.Close()
			o := enabled()
			o.MaxBytes = 128
			got, err := fetch.Get(context.Background(), s.URL+"/x", o)
			if code(err) != tc.want || len(got.Data) != 0 {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestTLSAndCancellation(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "hello"); err != nil {
			t.Error(err)
		}
	}))
	defer s.Close()
	o := enabled()
	o.RootCAs = x509.NewCertPool()
	o.RootCAs.AddCert(s.Certificate())
	if _, err := fetch.Get(context.Background(), s.URL+"/a", o); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetch.Get(ctx, s.URL, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	o.Timeout = 0
	if err := o.Validate(); err == nil {
		t.Fatal("zero timeout")
	}
	o.Timeout = 3 * time.Minute
	if err := o.Validate(); err == nil {
		t.Fatal("unbounded timeout")
	}
}

func FuzzResolveTarget(f *testing.F) {
	f.Add("https://example.com/a")
	f.Add("https://github.com/o/r")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		o := enabled()
		target, err := fetch.ResolveTarget(s, o)
		if err == nil && (target.URL == "" || target.Name == "" || strings.ContainsAny(target.Name, "/\\")) {
			t.Fatal("unsafe target")
		}
	})
}

func enabled() fetch.Options {
	o := fetch.DefaultOptions()
	o.Enabled = true
	o.AllowLoopback = true
	return o
}

func code(err error) string {
	if e, ok := errors.AsType[*fetch.Error](err); ok {
		return e.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
