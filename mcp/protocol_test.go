//nolint:testpackage // Tests exercise private JSON-RPC parsing and notification boundaries.
package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExactRequestWireContract(t *testing.T) {
	for _, id := range []string{`""`, `"request"`, `0`, `-9223372036854775808`, `9223372036854775807`, `"` + strings.Repeat("x", 96) + `"`, `"` + strings.Repeat(`\u0061`, 21) + `"`} {
		r, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"ping","id":` + id + `,"params":{}}`))
		if err != nil || string(r.ID) != id || string(r.Params) != "{}" || r.Method != "ping" {
			t.Fatal(r, err)
		}
	}
	for _, id := range []string{`null`, `true`, `[]`, `{}`, `1.0`, `1e1`, `9223372036854775808`, `"` + strings.Repeat("x", 97) + `"`, `"` + strings.Repeat(`\u0061`, 24) + `"`} {
		if _, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"ping","id":` + id + `}`)); err == nil {
			t.Fatal("invalid ID accepted", id)
		}
	}
	for _, wire := range []string{
		`null`, `{}`, `{"jsonrpc":"1.0","method":"ping"}`, `{"jsonrpc":"2.0","method":""}`,
		`{"jsonrpc":"2.0","method":"` + strings.Repeat("x", 129) + `"}`,
		`{"jsonrpc":"2.0","method":"ping","params":[]}`, `{"jsonrpc":"2.0","method":"ping","Params":{}}`,
		`{"jsonrpc":"2.0","Method":"ping"}`, `{"jsonrpc":"2.0","method":"ping","extra":0}`,
	} {
		if _, err := parseRequest([]byte(wire)); err == nil {
			t.Fatal("invalid envelope accepted", wire)
		}
	}
	if r, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"ping"}`)); err != nil || r.ID != nil || r.Params != nil {
		t.Fatal(r, err)
	}
	if _, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"` + strings.Repeat("x", 128) + `"}`)); err != nil {
		t.Fatal("inclusive method bound rejected", err)
	}
}

func TestAcceptHeaderRequiresEnabledExactJSONMedia(t *testing.T) {
	for _, header := range []string{"application/json", "text/plain, application/json;q=0.5", "application/json;q=1"} {
		if !acceptsJSON(header) {
			t.Fatal(header)
		}
	}
	for _, header := range []string{"", "*/*", "application/json-bogus", "application/json;broken", "application/json;q=0", "application/json;q=0.0", "application/json;q=0.00", "application/json;q=0.000", strings.Repeat("x", 4097)} {
		if acceptsJSON(header) {
			t.Fatal(header)
		}
	}
}

func TestNotificationsRespectSessionLifecycleAndCancellation(t *testing.T) {
	s := newSession()
	handleNotification(s, request{Method: "notifications/initialized"})
	if s.ready {
		t.Fatal("uninitialized session became ready")
	}
	s.initialized = true
	handleNotification(s, request{Method: "notifications/initialized"})
	if !s.ready {
		t.Fatal("initialized notification lost")
	}
	ctx, cancel := context.WithCancel(t.Context())
	s.pending[requestKey{kind: "number", value: "7"}] = cancel
	handleNotification(s, request{Method: "notifications/cancelled", Params: []byte(`{"requestId":8}`)})
	if ctx.Err() != nil {
		t.Fatal("unrelated request cancelled")
	}
	handleNotification(s, request{Method: "notifications/cancelled", Params: []byte(`{`)})
	if ctx.Err() != nil {
		t.Fatal("malformed cancellation admitted")
	}
	handleNotification(s, request{Method: "notifications/cancelled", Params: []byte(`{"requestId":7}`)})
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("request cancellation lost")
	}
}
