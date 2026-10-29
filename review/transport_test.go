package review_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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
