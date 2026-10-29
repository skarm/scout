package review_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/scout/review"
)

func TestHTTPProviderUsesOneToolFreeStructuredRequest(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer TEST_KEY" {
			t.Errorf("unexpected HTTP request %s %s", r.Method, r.URL.Path)
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
		}
		var req struct {
			Model         string
			Store, Stream bool
			Tools         []any
			ToolChoice    string `json:"tool_choice"`
			MaxTokens     int    `json:"max_completion_tokens"`
			Messages      []struct{ Role, Content string }
			Format        map[string]any `json:"response_format"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			t.Error(err)
		}
		if req.Model != "fixture-model" || req.Store || req.Stream || len(req.Tools) != 0 || req.ToolChoice != "none" || req.MaxTokens != 512 || len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[0].Content != expectedPrompt("discovery") || req.Messages[1].Role != "user" || req.Messages[1].Content != string(payload()) || req.Format["type"] != "json_schema" {
			t.Errorf("bad structured request")
		}
		if strings.Contains(string(b), "TEST_KEY") {
			t.Error("key included in prompt")
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, apiEnvelope(`{"request_id":"task"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	o := httpOptions(server.URL + "/v1/chat/completions")
	o.APIKey = "TEST_KEY"
	p, err := review.NewHTTP(o)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Complete(context.Background(), payload())
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Output) != `{"request_id":"task"}` || c.InputTokens != 10 || c.OutputTokens != 5 || c.Model != "fixture-returned-model" || calls.Load() != 1 {
		t.Fatalf("bad completion %+v calls=%d", c, calls.Load())
	}
	id := p.Identity()
	if strings.Contains(fmt.Sprintf("%+v", id), server.URL) || id.EndpointSHA256 == "" || id.SettingsSHA256 == "" {
		t.Fatal("identity leaks endpoint or lacks hashes")
	}
}

func TestHTTPRefusesUnexpectedResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType, encoding string
		status                            int
	}{
		{name: "status-secret", body: "SECRET_ERROR_BODY", contentType: "application/json", encoding: "", status: 401},
		{name: "html", body: "<html>SECRET_BODY</html>", contentType: "text/html", encoding: "", status: 200},
		{name: "compressed", body: apiEnvelope("{}"), contentType: "application/json", encoding: "gzip", status: 200},
		{
			name:        "case-alias",
			body:        `{"choices":[],"Choices":[]}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "duplicate",
			body:        `{"choices":[],"choices":[]}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{name: "malformed", body: "{", contentType: "application/json", encoding: "", status: 200},
		{name: "trailing", body: apiEnvelope("{}") + "{}", contentType: "application/json", encoding: "", status: 200},
		{name: "wrong-choices", body: `{"choices":[]}`, contentType: "application/json", encoding: "", status: 200},
		{
			name:        "truncated",
			body:        strings.Replace(apiEnvelope("{}"), `"stop"`, `"length"`, 1),
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "tool-call",
			body:        `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"{}","tool_calls":[{"function":{"name":"exec"}}]}}]}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "refusal",
			body:        `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"{}","refusal":"SECRET_REFUSAL"}}]}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "negative-usage",
			body:        strings.Replace(apiEnvelope("{}"), `"prompt_tokens":10`, `"prompt_tokens":-10`, 1),
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "no-content",
			body:        `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":null}}]}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
		{
			name:        "error-on-200",
			body:        `{"error":{"message":"SECRET_ERROR"}}`,
			contentType: "application/json",
			encoding:    "",
			status:      200,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, tc.body); err != nil {
					t.Error(err)
				}
			}))
			defer s.Close()
			p, e := review.NewHTTP(httpOptions(s.URL + "/api"))
			if e != nil {
				t.Fatal(e)
			}
			_, e = p.Complete(context.Background(), payload())
			if e == nil || strings.Contains(e.Error(), "SECRET") || calls.Load() != 1 {
				t.Fatalf("err=%v calls=%d", e, calls.Load())
			}
		})
	}
}

func TestHTTPRedirectNeverForwardsCredentials(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	o := httpOptions(s.URL + "/api")
	o.APIKey = "SECRET_KEY"
	p, e := review.NewHTTP(o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Complete(context.Background(), payload()); e == nil || targetCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
	if strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Error(), target.URL) {
		t.Fatal("error leaked endpoint")
	}
}

func TestHTTPResponseBudgetAndCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, strings.Repeat("x", 2000)); err != nil {
			t.Error(err)
		}
	}))
	defer s.Close()
	o := httpOptions(s.URL + "/api")
	o.MaxResponseBytes = 1024
	p, e := review.NewHTTP(o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Complete(context.Background(), payload()); e == nil {
		t.Fatal("oversize body accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = p.Complete(ctx, payload()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = p.Complete(nil, payload()); e == nil {
		t.Fatal("nil context accepted")
	}
	if _, e = p.Complete(context.Background(), []byte("invalid")); e == nil {
		t.Fatal("invalid request accepted")
	}
}

func TestHTTPSWithExplicitCA(t *testing.T) {
	certificate, root := localhostTLSCertificate(t)
	for _, tc := range []struct {
		name, endpoint string
		trusted, valid bool
	}{
		{name: "trusted", endpoint: "https://127.0.0.1/api", trusted: true, valid: true},
		{name: "untrusted", endpoint: "https://127.0.0.1/api", trusted: false, valid: false},
		{name: "wrong-host", endpoint: "https://[::1]/api", trusted: true, valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := httpOptions(tc.endpoint)
			o.Timeout = 5 * time.Second
			o.RootCAs = x509.NewCertPool()
			if tc.trusted {
				o.RootCAs.AddCert(root)
			}
			p, err := review.NewHTTP(o)
			if err != nil {
				t.Fatal(err)
			}
			// Capture the original error only for this credential-free local fixture.
			// Public provider errors deliberately omit network and endpoint details.
			client := review.HTTPClientForTest(p)
			// Keep the real HTTP/TLS transport, including its CA and hostname checks.
			// The fixture supplies the connection; it does not supply TLS verification.
			client.Transport.(*http.Transport).DialContext = localTLSDialer(t, certificate)
			transport := &observedHTTPTransport{base: client.Transport}
			client.Transport = transport
			_, err = p.Complete(t.Context(), payload())
			if tc.valid {
				if err != nil {
					t.Fatalf("trusted CA request failed: %v; transport cause: %T: %v", err, transport.err, transport.err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid server certificate accepted")
			}
			if _, ok := errors.AsType[*tls.CertificateVerificationError](transport.err); !ok {
				t.Fatalf("expected certificate rejection, got %v; transport cause: %T: %v", err, transport.err, transport.err)
			}
		})
	}
}

func localhostTLSCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, root
}

func tlsFixtureHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, apiEnvelope("{}")); err != nil {
			t.Error(err)
		}
	}
}

type observedHTTPTransport struct {
	base http.RoundTripper
	err  error
}

func (t *observedHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	t.err = err
	return response, err
}

func TestEndpointAndOptionValidation(t *testing.T) {
	for _, endpoint := range []string{"http://example.com/v1", "http://localhost/v1", "https://u:SECRET@example.com/v1", "https://example.com/v1?key=SECRET", "https://example.com/v1#fragment", "file:///tmp/test", "https://127.0.0.1:0/v1", "https://127.0.0.1:65536/v1", "https://10.0.0.1/v1", "https://169.254.169.254/v1", "https://100.100.100.200/v1", "https://[::ffff:10.0.0.1]/v1", "https://[fe80::1%25eth0]/v1", "https://example.com", "https://:443/v1", "https://example.com/v1?", "https://example.com/v%31", "https://[2001:db8::1]/v1"} {
		t.Run(endpoint, func(t *testing.T) {
			if _, e := review.NewHTTP(httpOptions(endpoint)); e == nil {
				t.Fatal("invalid endpoint accepted")
			} else if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("secret leaked")
			}
		})
	}
	for _, edit := range []func(*review.HTTPOptions){func(o *review.HTTPOptions) { o.AllowLoopback = false }, func(o *review.HTTPOptions) { o.Model = "bad\nmodel" }, func(o *review.HTTPOptions) { o.APIKey = "x\ny" }, func(o *review.HTTPOptions) { o.Timeout = 0 }, func(o *review.HTTPOptions) { o.MaxOutputTokens = 0 }, func(o *review.HTTPOptions) { o.MaxResponseBytes = 0 }} {
		o := httpOptions("http://127.0.0.1/v1")
		edit(&o)
		if _, e := review.NewHTTP(o); e == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, e := review.NewHTTP(httpOptions("https://api.example.com/v1/chat/completions")); e != nil {
		t.Fatal("public HTTPS should be configured without dialing", e)
	}
}

func TestOptionsValidateAndSchemaIsDefensive(t *testing.T) {
	o := review.DefaultOptions()
	o.Enabled = true
	if o.Validate() == nil {
		t.Fatal("consent not required")
	}
	o.AllowSourceUpload = true
	if e := o.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func(*review.Options){func(o *review.Options) { o.MaxRequests = 0 }, func(o *review.Options) { o.MaxRequests = 257 }, func(o *review.Options) { o.MaxInputBytes = 1 }, func(o *review.Options) { o.ChunkBytes = 1 }, func(o *review.Options) { o.MaxResponseBytes = 1 }, func(o *review.Options) { o.MaxProposals = 0 }, func(o *review.Options) { o.Timeout = 0 }} {
		x := o
		edit(&x)
		if x.Validate() == nil {
			t.Fatal("invalid options accepted")
		}
	}
	a := review.ResponseSchema()
	a["type"] = "bad"
	if review.ResponseSchema()["type"] != "object" {
		t.Fatal("mutable compiled schema")
	}
	if review.ErrorCode(errors.New("SECRET")) != "provider_failed" {
		t.Fatal("error leak")
	}
	if review.ErrorCode(context.DeadlineExceeded) != "timeout" {
		t.Fatal("deadline classification")
	}
}

func httpOptions(endpoint string) review.HTTPOptions {
	return review.HTTPOptions{
		Endpoint:         endpoint,
		Model:            "fixture-model",
		AllowLoopback:    true,
		Timeout:          time.Second,
		MaxOutputTokens:  512,
		MaxResponseBytes: 65536,
	}
}

func apiEnvelope(content string) string {
	v := map[string]any{
		"model":              "fixture-returned-model",
		"system_fingerprint": "fp",
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": "stop",
			"message": map[string]any{
				"role":    "assistant",
				"content": content,
			},
		}},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 5,
		},
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func payload() []byte {
	prompt, _ := review.PromptForMode("discovery")
	b, _ := json.Marshal(review.Request{
		SchemaVersion: review.ProtocolVersion,
		PromptVersion: review.PromptVersion,
		PromptSHA256:  review.PromptDigest(prompt),
		RequestID:     "task",
		Mode:          "discovery",
		Excerpts:      []review.Excerpt{},
		Findings:      []review.Finding{},
		Links:         []review.Link{},
	})
	return b
}

func expectedPrompt(mode string) string { p, _ := review.PromptForMode(mode); return p }
