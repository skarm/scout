package parse_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
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

type stub struct{ d parse.Descriptor }

func (s stub) Descriptor() parse.Descriptor                    { return s.d }
func (s stub) Parse(context.Context, source.View) (any, error) { return "immutable-test-tree", nil }
