package jsonconfig_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestJSON5ValuesAndOriginalSpans(t *testing.T) {
	const input = `{
		// комментарий
		\u0075rl: 'a\x2fb',
		words: 'line\
continuation',
		settings: { disabled: false, nullable: null, },
		numbers: [.5, +2., -0x2A, 1e-2, Infinity, -NaN,],
	}`
	root, err := jsonconfig.ParseJSON5(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}

	url := root.Get("url")
	if url.String != "a/b" || input[url.Span.Start:url.Span.End] != `'a\x2fb'` {
		t.Fatalf("wrong decoded value or source span: %+v", url)
	}

	key := root.Members[0].KeySpan
	if input[key.Start:key.End] != `\u0075rl` || root.Get("words").String != "linecontinuation" {
		t.Fatal("escaped property or line continuation was not decoded")
	}

	view, err := source.NewView(input, []source.Span{{End: len(input)}})
	if err != nil {
		t.Fatal(err)
	}

	decoded, ok := jsonconfig.StringView(view, url, 10)
	if !ok || decoded.Text() != "a/b" {
		t.Fatal("JSON5 string mapping failed")
	}

	slash, err := decoded.Original(source.Span{Start: 1, End: 2})
	if err != nil || input[slash.Start:slash.End] != `\x2f` {
		t.Fatalf("wrong original escape span: %+v, %v", slash, err)
	}

	for _, number := range root.Get("numbers").Elements {
		if number.Kind != jsonconfig.KindNumber || input[number.Span.Start:number.Span.End] != number.String {
			t.Fatalf("wrong number span or kind: %+v", number)
		}
	}
}

func TestJSON5RejectsAmbiguousInvalidAndUnboundedInput(t *testing.T) {
	for _, tc := range []struct{ name, input, code string }{
		{"duplicate", `{url: 1, "u\u0072l": 2}`, jsonconfig.CodeDuplicateKey},
		{"unquoted value", `{name: demo}`, "syntax_error"},
		{"leading zero", `{name: 01}`, "syntax_error"},
		{"numeric separator", `[1_000]`, "syntax_error"},
		{"unclosed comment", `{name: 1, /* forever`, "syntax_error"},
		{"invalid escape", `{name: '\01'}`, "syntax_error"},
		{"lone surrogate", `{name: '\uD800xuDC00'}`, "syntax_error"},
		{"trailing data", `{name: 1} {name: 2}`, "trailing_data"},
		{"depth", strings.Repeat("[", jsonconfig.MaxDepth+2) + strings.Repeat("]", jsonconfig.MaxDepth+2), "depth_limit"},
		{"nodes", "[" + strings.Repeat("0,", jsonconfig.MaxNodes) + "]", "node_limit"},
		{"bytes", strings.Repeat(" ", jsonconfig.MaxBytes+1), "byte_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var e *jsonconfig.Error
			if n, err := jsonconfig.ParseJSON5(t.Context(), tc.input); n != nil || !errors.As(err, &e) || e.Code != tc.code {
				t.Fatalf("want %q, got tree %v and error %v", tc.code, n, err)
			}
		})
	}
}

func FuzzJSON5SourceSpans(f *testing.F) {
	for _, text := range []string{`{}`, `{a: 1, "a": 2}`, `{δ: ['\x30', -0x11, null,],}`, `['\uD83D\uDE00']`, `[false, /* end */]`} {
		f.Add(text)
	}

	f.Fuzz(func(t *testing.T, text string) {
		root, err := jsonconfig.ParseJSON5(t.Context(), text)
		if err != nil {
			if root != nil {
				t.Fatal("invalid configuration returned a partial tree")
			}
			return
		}
		if root == nil {
			t.Fatal("missing JSON5 tree")
		}

		for item := range jsonconfig.Walk(t.Context(), root, jsonconfig.MaxDepth, jsonconfig.SourceOrder) {
			n := item.Node
			if n.Span.Start < 0 || n.Span.End <= n.Span.Start || n.Span.End > len(text) {
				t.Fatalf("invalid node span: %+v", n.Span)
			}

			for _, member := range n.Members {
				if member.KeySpan.Start < n.Span.Start || member.KeySpan.End > member.Value.Span.Start || member.Value.Span.End > n.Span.End {
					t.Fatalf("invalid member spans: %+v", member)
				}
			}
		}
	})
}
