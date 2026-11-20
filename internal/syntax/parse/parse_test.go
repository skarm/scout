package parse_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
)

func TestRegistryContract(t *testing.T) {
	good := stub{d: parse.Descriptor{
		ID:        "python-test",
		Language:  "python",
		Version:   "1",
		UnitBytes: 100,
		ScanBytes: 1000,
	}}
	r, err := parse.New(good)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := r.Lookup("python"); !ok || b.Descriptor().ID != "python-test" {
		t.Fatal("missing parser")
	}
	if _, ok := r.Lookup("go"); ok {
		t.Fatal("Go backend silently inserted")
	}
	if _, ok := parse.Defaults().Lookup("python"); ok {
		t.Fatal("claimed unimplemented Python parser")
	}
	for _, tc := range []struct {
		name     string
		backends []parse.Backend
	}{
		{name: "nil", backends: []parse.Backend{nil}},
		{name: "duplicate", backends: []parse.Backend{good, good}},
		{
			name: "untrusted-id",
			backends: []parse.Backend{stub{d: parse.Descriptor{
				ID:        "x",
				Language:  "SECRET_SENTINEL",
				Version:   "1",
				UnitBytes: 1,
				ScanBytes: 1,
			}}},
		},
		{name: "empty", backends: []parse.Backend{stub{}}},
		{
			name: "budget",
			backends: []parse.Backend{stub{d: parse.Descriptor{
				ID:        "x",
				Language:  "python",
				Version:   "1",
				UnitBytes: parse.MaxUnitBytes + 1,
				ScanBytes: parse.MaxScanBytes,
			}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse.New(tc.backends...); err == nil {
				t.Fatal("accepted invalid registry")
			}
		})
	}
}

func TestParserFailureCategoriesDoNotEchoInput(t *testing.T) {
	for _, tc := range []struct{ category, want string }{{category: "unsupported_syntax", want: "unsupported_syntax"}, {
		category: "parser_limit",
		want:     "parser_limit",
	}, {
		category: "SECRET_SENTINEL",
		want:     "syntax_error",
	}} {
		t.Run(tc.want+tc.category, func(t *testing.T) {
			e := &parse.Failure{Category: tc.category}
			if parse.FailureCategory(e) != tc.want || strings.Contains(e.Error(), "SECRET_SENTINEL") {
				t.Fatal("unsafe parser error category")
			}
		})
	}
	if parse.FailureCategory(errors.New("SECRET_SENTINEL")) != "syntax_error" {
		t.Fatal("error category escaped")
	}
}

func TestGoBindingLimitDoesNotPublishUnresolvedSyntax(t *testing.T) {
	backend, ok := parse.Defaults().Lookup("go")
	if !ok {
		t.Fatal("Go parser unavailable")
	}
	text := "package p; var x=" + strings.Repeat("(", 1024) + "1" + strings.Repeat(")", 1024)
	view, err := source.NewView(text, []source.Span{{End: len(text)}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := backend.Parse(t.Context(), view)
	if err == nil || parse.FailureCategory(err) != "parser_limit" {
		t.Fatalf("binding limit was not reported: %v", err)
	}
	tree, ok := raw.(parse.GoTree)
	if !ok || tree.Tree != nil {
		t.Fatal("unresolved syntax was admitted to Go analyzers")
	}
}

func TestDefaultShellBackend(t *testing.T) {
	backend, ok := parse.Defaults().Lookup("shell")
	if !ok {
		t.Fatal("missing Shell backend")
	}
	for _, tc := range []struct{ text, category string }{{text: "echo hi", category: ""}, {
		text:     "if true; then echo hi; fi",
		category: "unsupported_syntax",
	}, {
		text:     strings.Repeat("x", backend.Descriptor().UnitBytes+1),
		category: "parser_limit",
	}} {
		v, err := source.NewView(tc.text, []source.Span{{Start: 0, End: len(tc.text)}})
		if err != nil {
			t.Fatal(err)
		}
		tree, err := backend.Parse(context.Background(), v)
		if _, ok := tree.(parse.ShellTree); !ok {
			t.Fatal("wrong backend tree")
		}
		if tc.category == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || parse.FailureCategory(err) != tc.category {
			t.Fatalf("wrong failure: %v", err)
		}
	}
}

func TestEmbeddedBackendPreservesCallerCancellation(t *testing.T) {
	options := frontend.DefaultOptions()
	options.Python, options.YAML, options.TOML = true, true, true
	registry, err := parse.WithFrontends(options)
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()

	for _, format := range []string{"python", "yaml", "toml"} {
		t.Run(format, func(t *testing.T) {
			backend, ok := registry.Lookup(format)
			if !ok {
				t.Fatal("embedded frontend missing")
			}
			for _, ctx := range []context.Context{cancelled, expired} {
				tree, err := backend.Parse(ctx, source.View{})
				if tree != nil || !errors.Is(err, ctx.Err()) {
					t.Fatalf("tree=%T, error=%v, want %v", tree, err, ctx.Err())
				}
			}
		})
	}
}

func TestEmbeddedBackendClassifiesOwnDeadlineAsLimit(t *testing.T) {
	if !frontend.BackendFor("yaml").Available {
		t.Skip("YAML frontend unavailable")
	}

	registry, err := parse.WithFrontends(frontend.Options{YAML: true, Timeout: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	backend, ok := registry.Lookup("yaml")
	if !ok {
		t.Fatal("YAML frontend missing")
	}
	view, err := source.NewView("name: sample", []source.Span{{End: len("name: sample")}})
	if err != nil {
		t.Fatal(err)
	}

	tree, err := backend.Parse(t.Context(), view)
	if tree != nil || err == nil || parse.FailureCategory(err) != "parser_limit" {
		t.Fatalf("tree=%T, error=%v, want parser_limit", tree, err)
	}
}

func TestSQLBudgetFailureRetainsEarlierStatements(t *testing.T) {
	backend, ok := parse.Defaults().Lookup("sql")
	if !ok {
		t.Fatal("missing SQL backend")
	}

	for _, tc := range []struct{ name, text, category string }{
		{name: "bytes", text: strings.Repeat(" ", sqlsyntax.MaxBytes) + "SELECT 2;", category: "parser_limit"},
		{name: "tokens", text: "SELECT " + strings.Repeat("1+", sqlsyntax.MaxTokens/2) + "1;", category: "parser_limit"},
		{name: "parentheses", text: "SELECT " + strings.Repeat("(", sqlsyntax.MaxDepth+1) + "2" + strings.Repeat(")", sqlsyntax.MaxDepth+1) + ";", category: "parser_limit"},
		{name: "comment", text: strings.Repeat("/* ", sqlsyntax.MaxDepth+1) + strings.Repeat(" */", sqlsyntax.MaxDepth+1), category: "parser_limit"},
		{name: "syntax", text: "SELECT (2;", category: "syntax_error"},
		{name: "encoding", text: "SELECT \xff;", category: "syntax_error"},
		{name: "unsupported", text: "CALL fn();", category: "unsupported_syntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const earlier = "SELECT 1"

			text := earlier + "; " + tc.text
			view, err := source.NewView(text, []source.Span{{End: len(text)}})
			if err != nil {
				t.Fatal(err)
			}

			raw, err := backend.Parse(t.Context(), view)
			if got := parse.FailureCategory(err); err == nil || got != tc.category {
				t.Fatalf("category = %s (%v), want %s", got, err, tc.category)
			}

			tree, ok := raw.(sqlsyntax.Tree)
			if !ok {
				t.Fatalf("invalid tree type: %T", raw)
			}

			if tc.name != "bytes" && tc.name != "encoding" && (len(tree.Statements) == 0 || tree.Statements[0].Start != 0 || tree.Statements[0].End != len(earlier)) {
				t.Fatal("first statement lost or source span changed")
			}
		})
	}
}

func TestScriptBudgetFailureAndCancellation(t *testing.T) {
	for _, lang := range []string{"javascript", "typescript"} {
		t.Run(lang, func(t *testing.T) {
			backend, ok := parse.Defaults().Lookup(lang)
			if !ok {
				t.Skip("script parser unavailable")
			}

			for _, tc := range []struct{ name, text, category string }{
				{name: "bytes", text: strings.Repeat(" ", backend.Descriptor().UnitBytes) + "const x = 1;", category: "parser_limit"},
				{name: "depth", text: "const x = " + strings.Repeat("(", 66) + "1" + strings.Repeat(")", 66) + ";", category: "parser_limit"},
				{name: "syntax", text: "const x = ;", category: "syntax_error"},
				{name: "encoding", text: "const x = '\xff';", category: "syntax_error"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					view, err := source.NewView(tc.text, []source.Span{{End: len(tc.text)}})
					if err != nil {
						t.Fatal(err)
					}

					_, err = backend.Parse(t.Context(), view)
					if got := parse.FailureCategory(err); err == nil || got != tc.category {
						t.Fatalf("category = %s (%v), want %s", got, err, tc.category)
					}
				})
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			if _, err := backend.Parse(ctx, source.View{}); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was lost", err)
			}
		})
	}
}

type stub struct{ d parse.Descriptor }

func (s stub) Descriptor() parse.Descriptor                    { return s.d }
func (s stub) Parse(context.Context, source.View) (any, error) { return "immutable-test-tree", nil }
