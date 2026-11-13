package review_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
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
	for _, family := range []string{"chat", "messages"} {
		t.Run(family, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider, client := testProvider(t, family)
				client.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
					<-r.Context().Done()
					return nil, r.Context().Err()
				})

				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				_, err := provider.Complete(ctx, payload())
				if !errors.Is(err, context.DeadlineExceeded) || review.ErrorCode(err) != "timeout" || ctx.Err() != nil {
					t.Fatalf("waiting for response headers: got %v (%s), parent context %v; want client timeout", err, review.ErrorCode(err), ctx.Err())
				}
			})
		})
	}
}

func TestProviderFamiliesPreserveCancellationDuringResponseBody(t *testing.T) {
	for _, family := range []string{"chat", "messages"} {
		for _, tc := range []struct {
			name string
			want error
			code string
		}{
			{name: "cancel", want: context.Canceled, code: "cancelled"},
			{name: "context-deadline", want: context.DeadlineExceeded, code: "timeout"},
			{name: "client-deadline", want: context.DeadlineExceeded, code: "timeout"},
		} {
			t.Run(family+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					provider, client := testProvider(t, family)
					parentTimeout := time.Second
					if tc.name == "context-deadline" {
						parentTimeout = 10 * time.Millisecond
					}

					ctx, cancel := context.WithTimeout(t.Context(), parentTimeout)
					defer cancel()
					read := false
					client.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
						body := readerFunc(func([]byte) (int, error) {
							read = true
							if tc.name == "cancel" {
								cancel()
							}

							<-r.Context().Done()
							return 0, r.Context().Err()
						})
						return &http.Response{
							StatusCode:    http.StatusOK,
							Header:        http.Header{"Content-Type": []string{"application/json"}},
							Body:          io.NopCloser(body),
							ContentLength: -1,
						}, nil
					})

					_, err := provider.Complete(ctx, payload())
					if !read || !errors.Is(err, tc.want) || review.ErrorCode(err) != tc.code {
						t.Fatalf("reading response body: read=%t, got %v (%s), want %v (%s)", read, err, review.ErrorCode(err), tc.want, tc.code)
					}

					if tc.name == "client-deadline" && ctx.Err() != nil {
						t.Fatalf("client timeout fell back to parent context: %v", ctx.Err())
					}
				})
			})
		}
	}
}

// Keep the provider's real http.Client so its Timeout still controls the request.
func testProvider(t *testing.T, family string) (review.Provider, *http.Client) {
	t.Helper()
	opts := httpOptions("https://example.com/review")
	opts.Timeout = 20 * time.Millisecond
	if family == "messages" {
		p, err := review.NewMessages(review.MessagesOptions{HTTPOptions: opts, Transport: "anthropic"})
		if err != nil {
			t.Fatal(err)
		}

		return p, review.MessagesHTTPClientForTest(p)
	}

	p, err := review.NewHTTP(opts)
	if err != nil {
		t.Fatal(err)
	}

	return p, review.HTTPClientForTest(p)
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Body.Close(); err != nil {
		return nil, err
	}

	return f(r)
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }
