package jsonconfig_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func TestStrictJSON(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
		{name: "empty-object", text: `{}`, code: ""},
		{name: "scalar", text: `42`, code: ""},
		{name: "array", text: `[true,false,null,-2,{},[]]`, code: ""},
		{name: "unicode", text: `{"\u0070ermissions":"Привет\ud83d\ude80"}`, code: ""},
		{name: "replacement", text: `["�","\ufffd"]`, code: ""},
		{name: "duplicate", text: `{"x":1,"x":2}`, code: "duplicate_key"},
		{name: "escaped-duplicate", text: `{"x":1,"\u0078":2}`, code: "duplicate_key"},
		{name: "nested-duplicate", text: `{"x":{"x":1,"x":2}}`, code: "duplicate_key"},
		{name: "separate-scopes", text: `{"x":{"x":1},"y":{"x":2}}`, code: ""},
		{name: "high-surrogate", text: `"\ud800"`, code: "invalid_unicode"},
		{name: "low-surrogate", text: `"\udc00"`, code: "invalid_unicode"},
		{name: "bad-pair", text: `"\ud800\u0061"`, code: "invalid_unicode"},
		{name: "escaped-backslash", text: `"\\ud800"`, code: ""},
		{name: "invalid-bytes", text: "\"\xff\"", code: "invalid_unicode"},
		{name: "trailing", text: `{} {}`, code: "trailing_data"},
		{name: "comment", text: `{"x":1// bad`, code: "syntax_error"},
		{name: "trailing-comma", text: `{"x":1,}`, code: "syntax_error"},
		{name: "empty", text: "", code: "syntax_error"},
		{
			name: "depth",
			text: strings.Repeat("[", jsonconfig.MaxDepth+2) + "1" + strings.Repeat("]", jsonconfig.MaxDepth+2),
			code: "depth_limit",
		},
		{name: "nodes", text: "[" + strings.Repeat("0,", jsonconfig.MaxNodes) + "0]", code: "node_limit"},
		{name: "bytes", text: strings.Repeat(" ", jsonconfig.MaxBytes+1), code: "byte_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := jsonconfig.Parse(context.Background(), tc.text)
			if tc.code == "" {
				if err != nil || n == nil {
					t.Fatalf("%v", err)
				}
				verifyTree(t, tc.text, n)
				return
			}
			var failure *jsonconfig.Error
			if n != nil || !errors.As(err, &failure) || failure.Code != tc.code {
				t.Fatalf("got tree=%v error=%v", n, err)
			}
		})
	}
}

func TestLocationsAndGet(t *testing.T) {
	s := " \r\n {\"permissions\" : {\"defaultMode\": \"bypassPermissions\"}, \"values\": [ 1, 2 ]}  "
	n, err := jsonconfig.Parse(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	verifyTree(t, s, n)
	v := n.Get("permissions").Get("defaultMode")
	text, ok := v.Text()
	if !ok || text != "bypassPermissions" || s[v.Span.Start:v.Span.End] != `"bypassPermissions"` {
		t.Fatalf("bad value %+v", v)
	}
	if _, ok := n.Get("unknown").Text(); ok {
		t.Fatal("missing field got a value")
	}
	if n.Get("values").Get("anything") != nil {
		t.Fatal("array has object fields")
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := jsonconfig.Parse(ctx, `{}`); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := jsonconfig.Parse(nil, `{}`); err == nil {
		t.Fatal("accepted nil context")
	}
}

func FuzzJSONConfig(f *testing.F) {
	for _, s := range []string{`{}`, `{"permissions":{"defaultMode":"bypassPermissions"}}`, `{"x":1,"\u0078":2}`, `["\ud800",false]`, `{"x":[{},"hello",-2.0]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > jsonconfig.MaxBytes+1 {
			t.Skip()
		}
		n, err := jsonconfig.Parse(context.Background(), s)
		if err != nil {
			if n != nil {
				t.Fatal("partial ambiguous tree")
			}
			return
		}
		if !json.Valid([]byte(s)) {
			t.Fatal("accepted invalid JSON")
		}
		verifyTree(t, s, n)
	})
}

func TestExplicitNodeLimitPreservesDefaultAndExactBoundary(t *testing.T) {
	text := "[" + strings.Repeat("0,", jsonconfig.MaxNodes-1) + "0]"
	if _, err := jsonconfig.Parse(context.Background(), text); err == nil {
		t.Fatal("default node budget was relaxed")
	}
	n, err := jsonconfig.ParseWithNodeLimit(context.Background(), text, jsonconfig.MaxNodes+1)
	if err != nil || len(n.Elements) != jsonconfig.MaxNodes {
		t.Fatalf("bounded override rejected exact node limit: %v", err)
	}
	if _, err := jsonconfig.ParseWithNodeLimit(context.Background(), "[0,0]", 3); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonconfig.ParseWithNodeLimit(context.Background(), "[0,0]", 2); err == nil {
		t.Fatal("explicit node limit was not enforced")
	}
}

func TestExplicitNodeLimitRetainsStrictParsingAndCancellation(t *testing.T) {
	for _, limit := range []int{-1, 0, jsonconfig.MaxBytes + 1} {
		_, err := jsonconfig.ParseWithNodeLimit(context.Background(), "null", limit)
		var failure *jsonconfig.Error
		if !errors.As(err, &failure) || failure.Code != "invalid_node_limit" {
			t.Fatalf("limit=%d error=%v", limit, err)
		}
	}
	for _, text := range []string{`{"x":1,"x":2}`, `"\ud800"`, strings.Repeat("[", jsonconfig.MaxDepth+2) + "0" + strings.Repeat("]", jsonconfig.MaxDepth+2), strings.Repeat(" ", jsonconfig.MaxBytes+1)} {
		if _, err := jsonconfig.ParseWithNodeLimit(context.Background(), text, jsonconfig.MaxBytes); err == nil {
			t.Fatal("node override relaxed strict parsing")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := jsonconfig.ParseWithNodeLimit(ctx, "{}", 8); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := jsonconfig.ParseWithNodeLimit(nil, "{}", 8); err == nil {
		t.Fatal("accepted nil context")
	}
}

func TestCancellationSchedulesAtCooperativePollingBoundaries(t *testing.T) {
	const text = `{"items":[1,{"value":"ok"}]}`
	cancelled, completed := false, false
	for budget := int32(0); budget <= 16; budget++ {
		base, cancel := context.WithCancel(context.Background())
		ctx := &pollBudgetContext{Context: base, cancel: cancel}
		ctx.remaining.Store(budget)
		n, err := jsonconfig.ParseWithNodeLimit(ctx, text, len(text))
		if base.Err() != nil {
			cancelled = true
			if n != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled parse published a tree: budget=%d tree=%v error=%v", budget, n, err)
			}
		} else {
			completed = true
			if n == nil || err != nil {
				t.Fatalf("uncancelled parse failed: budget=%d tree=%v error=%v", budget, n, err)
			}
			verifyTree(t, text, n)
		}
		cancel()
	}
	if !cancelled || !completed {
		t.Fatal("schedules must exercise both cancelled and completed parses")
	}
}

func TestStringUnicodeRequiresOneIntactTokenEnvelope(t *testing.T) {
	for _, raw := range []string{"", `plain`, `"unterminated`, `unopened"`, "\"\\\"", `"\u"`, `"\uZZZZ"`, "\"\xff\""} {
		if jsonconfig.ValidStringUnicode(raw) {
			t.Fatalf("invalid string token envelope or scalar encoding accepted: %q", raw)
		}
	}
	if !jsonconfig.ValidStringUnicode(`""`) {
		t.Fatal("empty string token rejected")
	}
}

func verifyTree(t testing.TB, text string, n *jsonconfig.Node) {
	t.Helper()
	if n.Span.Start < 0 || n.Span.End <= n.Span.Start || n.Span.End > len(text) {
		t.Fatal("invalid node span")
	}
	if !json.Valid([]byte(text[n.Span.Start:n.Span.End])) {
		t.Fatal("node span is not a JSON value")
	}
	for _, m := range n.Members {
		if m.KeySpan.Start < n.Span.Start || m.KeySpan.End > n.Span.End {
			t.Fatal("key outside parent")
		}
		var key string
		if err := json.Unmarshal([]byte(text[m.KeySpan.Start:m.KeySpan.End]), &key); err != nil || key != m.Key {
			t.Fatal("incorrect key mapping")
		}
		verifyTree(t, text, m.Value)
	}
	for _, c := range n.Elements {
		verifyTree(t, text, c)
	}
}

// Use real cancellation at different cooperative polling boundaries. Assertions
// inspect the underlying context instead of assuming an exact poll count/order.
type pollBudgetContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining atomic.Int32
}

func (c *pollBudgetContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.remaining.Add(-1) < 0 {
		c.cancel()
	}
	return c.Context.Err()
}
