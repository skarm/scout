package review_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/review"
)

func TestDownloadAndReviewerUseTheSameAddressPolicy(t *testing.T) {
	for _, address := range []string{"192.88.99.1", "2001::1", "3fff::1", "10.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "8.8.8.8", "2606:4700:4700::1111"} {
		t.Run(address, func(t *testing.T) {
			endpoint := "https://" + net.JoinHostPort(address, "443") + "/v1/chat/completions"
			o := fetch.DefaultOptions()
			o.Enabled = true
			_, downloadErr := fetch.ResolveTarget(endpoint, o)
			_, reviewErr := review.NewHTTP(httpOptions(endpoint))
			if (downloadErr == nil) != (reviewErr == nil) {
				t.Fatalf("address policy differs: download=%v review=%v", downloadErr, reviewErr)
			}
		})
	}
}

func TestProviderFamiliesTreatContentCodingNamesWithoutCase(t *testing.T) {
	for _, family := range []string{"chat", "messages"} {
		for _, codings := range [][]string{nil, {"identity"}, {"Identity"}, {"IDENTITY"}, {"gzip"}, {"GZip"}, {"br"}, {"identity, gzip"}, {"identity", "gzip"}} {
			t.Run(family+"/"+strings.Join(codings, "|"), func(t *testing.T) {
				body := apiEnvelope("{}")
				if family == "messages" {
					body = `{"type":"message","role":"assistant","model":"fixture","stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}`
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					for _, coding := range codings {
						w.Header().Add("Content-Encoding", coding)
					}
					if _, err := io.WriteString(w, body); err != nil {
						t.Error(err)
					}
				}))
				defer server.Close()
				opts := httpOptions(server.URL + "/review")
				var provider review.Provider
				var err error
				if family == "chat" {
					provider, err = review.NewHTTP(opts)
				} else {
					provider, err = review.NewMessages(review.MessagesOptions{HTTPOptions: opts, Transport: "anthropic"})
				}
				if err != nil {
					t.Fatal(err)
				}
				completion, err := provider.Complete(context.Background(), payload())
				if len(codings) == 0 || len(codings) == 1 && strings.EqualFold(codings[0], "identity") {
					if err != nil || string(completion.Output) != "{}" {
						t.Fatalf("uncompressed JSON rejected: output=%q err=%v", completion.Output, err)
					}
				} else if review.ErrorCode(err) != "transport_content_encoding" {
					t.Fatalf("unsupported content coding accepted: err=%v", err)
				}
			})
		}
	}
}

func TestProviderFamiliesPreserveClientDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(100 * time.Millisecond) }))
	defer server.Close()
	opts := review.HTTPOptions{
		Endpoint:         server.URL + "/review",
		Model:            "fixture",
		AllowLoopback:    true,
		Timeout:          20 * time.Millisecond,
		MaxOutputTokens:  128,
		MaxResponseBytes: 1024,
	}
	chat, err := review.NewHTTP(opts)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := review.NewMessages(review.MessagesOptions{HTTPOptions: opts, Transport: "anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := review.PromptForMode("discovery")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(review.Request{
		SchemaVersion: review.ProtocolVersion,
		PromptVersion: review.PromptVersion,
		Mode:          "discovery",
		PromptSHA256:  review.PromptDigest(prompt),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []review.Provider{chat, messages} {
		_, err = p.Complete(context.Background(), payload)
		if !errors.Is(err, context.DeadlineExceeded) || review.ErrorCode(err) != "timeout" {
			t.Fatalf("%s lost timeout identity: %v (%s)", p.Identity().Provider, err, review.ErrorCode(err))
		}
	}
}

func TestProviderFamiliesPreserveCancellationDuringResponseBody(t *testing.T) {
	for _, family := range []string{"chat", "messages"} {
		for _, stop := range []string{"cancel", "context-deadline", "client-deadline"} {
			t.Run(family+"/"+stop, func(t *testing.T) {
				started := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Error(err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.(http.Flusher).Flush()
					close(started)
					<-r.Context().Done()
				}))
				defer server.Close()
				opts := httpOptions(server.URL + "/review")
				if stop == "client-deadline" {
					opts.Timeout = 100 * time.Millisecond
				}
				var provider review.Provider
				var err error
				if family == "chat" {
					provider, err = review.NewHTTP(opts)
				} else {
					provider, err = review.NewMessages(review.MessagesOptions{HTTPOptions: opts, Transport: "anthropic"})
				}
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				if stop == "context-deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				}
				defer cancel()
				if stop == "cancel" {
					go func() {
						select {
						case <-started:
							cancel()
						case <-ctx.Done():
						}
					}()
				}
				_, err = provider.Complete(ctx, payload())
				want, code := context.DeadlineExceeded, "timeout"
				if stop == "cancel" {
					want, code = context.Canceled, "cancelled"
				}
				if !errors.Is(err, want) || review.ErrorCode(err) != code {
					t.Fatalf("body read lost cancellation: %v (%s), want %v", err, review.ErrorCode(err), want)
				}
			})
		}
	}
}
