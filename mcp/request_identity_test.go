//nolint:testpackage // Tests exercise private request correlation keys and admission cancellation.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestLogicalRequestIDsShareCancellationAndDuplicateDetection(t *testing.T) {
	for _, ids := range [][2]string{{`"\u0061"`, `"a"`}, {`"a\/b"`, `"a/b"`}, {`-0`, `0`}} {
		t.Run(ids[0], func(t *testing.T) {
			server := &Server{options: Options{Timeout: time.Second}, slots: make(chan struct{}, 2)}
			sess := newSession()
			first, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"tools/call","id":` + ids[0] + `}`))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cleanup, rejected := server.accept(context.Background(), sess, first)
			if rejected != nil {
				t.Fatal(rejected)
			}
			defer cleanup()
			second, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"tools/call","id":` + ids[1] + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, release, duplicate := server.accept(context.Background(), sess, second); duplicate == nil {
				release()
				t.Error("accepted a duplicate logical request ID")
			}
			handleNotification(sess, request{
				Method: "notifications/cancelled",
				Params: json.RawMessage(`{"requestId":` + ids[1] + `}`),
			})
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Error("equivalent cancellation ID did not cancel the active request")
			}
			if encoded := encodeResponse(rpcFailure(first.ID, -32000, "fixture")); !bytes.Contains(encoded, []byte(`"id":`+ids[0]+`,`)) {
				t.Fatal("correlation normalization changed response ID echo")
			}
		})
	}
}

func TestStringAndNumberRequestIDsRemainDistinct(t *testing.T) {
	server := &Server{options: Options{Timeout: time.Second}, slots: make(chan struct{}, 2)}
	sess := newSession()
	contexts := make([]context.Context, 0, 2)
	for _, id := range []string{`"7"`, `7`} {
		r, err := parseRequest([]byte(`{"jsonrpc":"2.0","method":"tools/call","id":` + id + `}`))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cleanup, rejected := server.accept(context.Background(), sess, r)
		if rejected != nil {
			t.Fatal("different JSON ID types collided")
		}
		t.Cleanup(cleanup)
		contexts = append(contexts, ctx)
	}
	handleNotification(sess, request{Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":7}`)})
	if contexts[0].Err() != nil || !errors.Is(contexts[1].Err(), context.Canceled) {
		t.Fatal("numeric cancellation affected the wrong ID type")
	}
}
