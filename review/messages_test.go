package review_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/review"
)

func TestNativeMessagesTransports(t *testing.T) {
	for _, kind := range []string{"anthropic", "anthropic-proxy", "bedrock"} {
		t.Run(kind, func(t *testing.T) {
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]json.RawMessage
				raw, _ := io.ReadAll(r.Body)
				if json.Unmarshal(raw, &body) != nil {
					t.Error("bad request")
				}
				if body["tools"] != nil || body["tool_choice"] != nil {
					t.Error("tools enabled")
				}
				if !strings.Contains(string(body["system"]), "UNTRUSTED DATA") {
					t.Error("system prompt missing")
				}
				if kind == "anthropic" {
					if r.Header.Get("X-Api-Key") != "secret-key" || r.Header.Get("Anthropic-Version") != "2023-06-01" {
						t.Error("anthropic auth")
					}
					if body["model"] == nil {
						t.Error("missing model")
					}
				}
				if kind == "anthropic-proxy" {
					if r.Header.Get("Authorization") != "Bearer secret-key" || string(body["anthropic_version"]) != `"vertex-2023-10-16"` {
						t.Error("proxy auth")
					}
				}
				if kind == "bedrock" {
					if body["model"] != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE1234/") {
						t.Error("bedrock auth")
					}
					if r.Header.Get("X-Amz-Security-Token") != "test-session" {
						t.Error("missing temporary token")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, `{"type":"message","role":"assistant","model":"test-model","stop_reason":"end_turn","content":[{"type":"text","text":"{}"}],"usage":{"input_tokens":3,"output_tokens":2}}`); err != nil {
					t.Error(err)
				}
			}))
			defer service.Close()
			opts := review.MessagesOptions{
				HTTPOptions: review.HTTPOptions{
					Endpoint:         service.URL + "/v1/messages",
					Model:            "test-model",
					APIKey:           "secret-key",
					AllowLoopback:    true,
					Timeout:          time.Second,
					MaxOutputTokens:  128,
					MaxResponseBytes: 4096,
				},
				Transport: kind,
			}
			if kind == "bedrock" {
				opts.Endpoint = service.URL + "/model/test-model/invoke"
				opts.APIKey = ""
				opts.Region = "us-east-1"
				opts.AccessKeyID = "AKIDEXAMPLE1234"
				opts.SecretAccessKey = "test-secret"
				opts.SessionToken = "test-session"
			}
			p, e := review.NewMessages(opts)
			if e != nil {
				t.Fatal(e)
			}
			c, e := p.Complete(context.Background(), payload())
			if e != nil || string(c.Output) != "{}" || c.InputTokens != 3 {
				t.Fatalf("%+v %v", c, e)
			}
		})
	}
}

func TestMessagesRejectToolTruncatedAndDuplicateResponses(t *testing.T) {
	for _, raw := range []string{
		`{"type":"message","role":"assistant","stop_reason":"max_tokens","content":[{"type":"text","text":"{}"}]}`,
		`{"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"tool_use","name":"exec","input":{}}]}`,
		`{"type":"message","role":"assistant","stop_reason":"end_turn","stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}`,
		`{"type":"message","Role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}`,
	} {
		t.Run(raw[:min(30, len(raw))], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, raw); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			p, e := review.NewMessages(review.MessagesOptions{HTTPOptions: review.HTTPOptions{
				Endpoint:         srv.URL + "/messages",
				Model:            "test",
				AllowLoopback:    true,
				Timeout:          time.Second,
				MaxOutputTokens:  128,
				MaxResponseBytes: 4096,
			}})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = p.Complete(context.Background(), payload()); e == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestMessagesCredentialsAreExplicitAndTransportSpecific(t *testing.T) {
	base := review.MessagesOptions{
		HTTPOptions: review.HTTPOptions{
			Endpoint:         "http://127.0.0.1/model/fixture/invoke",
			Model:            "fixture",
			AllowLoopback:    true,
			Timeout:          time.Second,
			MaxOutputTokens:  128,
			MaxResponseBytes: 1024,
		},
		Transport:       "bedrock",
		Region:          "us-east-1",
		AccessKeyID:     "FIXTUREKEY",
		SecretAccessKey: "fixture-secret",
	}
	if _, err := review.NewMessages(base); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*review.MessagesOptions){
		func(o *review.MessagesOptions) { o.Endpoint = "http://127.0.0.1/model/other/invoke" },
		func(o *review.MessagesOptions) { o.APIKey = "mixed-auth" },
		func(o *review.MessagesOptions) { o.SessionToken = "bad\nvalue" },
		func(o *review.MessagesOptions) { o.Transport = "anthropic" },
	} {
		o := base
		change(&o)
		if _, err := review.NewMessages(o); err == nil {
			t.Fatal("invalid transport credentials admitted")
		}
	}
}

// Independent golden produced offline by botocore 1.43.18 SigV4Auth, using
// synthetic credentials. No AWS service or live credential was used.
func TestBedrockSignatureAgainstBotocoreGolden(t *testing.T) {
	r, _ := http.NewRequestWithContext(t.Context(), "POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.test-v1:0/invoke", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	review.SignBedrockForTest(r, []byte(`{"sample":true}`), review.MessagesOptions{
		Region:          "us-east-1",
		AccessKeyID:     "AKIDEXAMPLE1234",
		SecretAccessKey: "test-secret-do-not-use",
		SessionToken:    "SESSION_TEST",
	}, time.Date(2026, 10, 26, 10, 20, 30, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE1234/20261026/us-east-1/bedrock/aws4_request, SignedHeaders=accept;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=9b26ca9e803118faccf6e77cc84f2ce5fd9c306e9644e369b15174443613239f"
	if got := r.Header.Get("Authorization"); got != want {
		t.Fatalf("signature mismatch: %s", got)
	}
}
