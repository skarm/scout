//nolint:testpackage // Exercises admission after transport session removal, including a request that already passed readiness.
package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRemovedSessionRejectsLateAdmission(t *testing.T) {
	server := &Server{options: DefaultOptions(), slots: make(chan struct{}, 2)}
	sess := newSession()
	sess.initialized, sess.ready = true, true
	first := request{ID: json.RawMessage(`1`), key: requestKey{kind: "number", value: "1"}}
	active, finish, rejected := server.accept(t.Context(), sess, first)
	if rejected != nil {
		t.Fatal("active request rejected", rejected)
	}
	defer finish()

	cancelSession(sess)
	if active.Err() != context.Canceled {
		t.Fatal("session removal did not cancel the active request", active.Err())
	}

	// This request can already hold the session pointer and have passed the
	// readiness check when an HTTP DELETE removes the session from the map.
	late := request{ID: json.RawMessage(`2`), key: requestKey{kind: "number", value: "2"}}
	_, cleanup, rejected := server.accept(t.Context(), sess, late)
	if cleanup != nil {
		cleanup()
	}
	if rejected == nil || rejected.Error == nil {
		t.Fatal("removed session admitted a fresh scan")
	}
	if len(server.slots) != 1 {
		t.Fatal("rejected admission leaked a concurrency slot")
	}
	handleNotification(sess, request{Method: "notifications/initialized"})
	if sessionReady(sess) {
		t.Fatal("late notification revived a removed session")
	}
}

func TestHTTPDeleteReturnsNotFoundForExpiredSession(t *testing.T) {
	const id = "test-session"
	for _, tc := range []struct {
		name   string
		age    time.Duration
		status int
	}{
		{"active", time.Minute, http.StatusNoContent},
		{"expired", 16 * time.Minute, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession()
			sess.created = time.Now().Add(-tc.age)
			opts := DefaultOptions()
			opts.HTTPToken = strings.Repeat("T", 40)
			server := &Server{options: opts, sessions: map[string]*session{id: sess}}
			handler, err := server.HTTPHandler()
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+opts.HTTPToken)
			req.Header.Set("Mcp-Session-Id", id)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.status {
				t.Fatalf("DELETE returned status %d, want %d", res.Code, tc.status)
			}
			if _, present := server.sessions[id]; present || !sess.closed {
				t.Fatal("DELETE did not remove and close the session")
			}
		})
	}
}

func TestHTTPInitializationDiscardsUnpublishedSession(t *testing.T) {
	for _, name := range []string{"request cancelled", "response write failed", "session limit"} {
		t.Run(name, func(t *testing.T) {
			opts := DefaultOptions()
			opts.HTTPToken = strings.Repeat("T", 40)
			server := &Server{options: opts, sessions: map[string]*session{}}
			handler, err := server.HTTPHandler()
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			recorder := httptest.NewRecorder()
			var writer http.ResponseWriter = recorder
			wantSessions := 0
			switch name {
			case "request cancelled":
				cancel()
			case "response write failed":
				writer = closedHTTPResponse{recorder}
			case "session limit":
				for i := range maxHTTPSessions {
					server.sessions[strconv.Itoa(i)] = newSession()
				}
				wantSessions = maxHTTPSessions
			}
			const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(initialize))
			req.Header.Set("Authorization", "Bearer "+opts.HTTPToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			handler.ServeHTTP(writer, req)
			if name == "session limit" && recorder.Code != http.StatusTooManyRequests {
				t.Errorf("HTTP initialization returned %d at the session limit, want %d", recorder.Code, http.StatusTooManyRequests)
			}
			if got := len(server.sessions); got != wantSessions {
				t.Errorf("HTTP initialization left %d sessions, want %d", got, wantSessions)
			}
		})
	}
}

type closedHTTPResponse struct{ http.ResponseWriter }

func (closedHTTPResponse) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
