package jsonconfig_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func TestJSONCPreservesOriginalOffsets(t *testing.T) {
	const input = "{ /* комментарий */ \"url\": \"https://example.invalid/*literal*/\", // comment\n \"args\": [\"ok\",],\n}"
	root, err := jsonconfig.ParseJSONC(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*jsonconfig.Node{root.Get("url"), root.Get("args").Elements[0]} {
		if got := input[n.Span.Start:n.Span.End]; got != "\""+n.String+"\"" {
			t.Fatalf("wrong original span: %q for %q", got, n.String)
		}
	}
	if _, err := jsonconfig.Parse(t.Context(), input); err == nil {
		t.Fatal("strict JSON accepted JSONC")
	}
}

func TestJSONWithCommentsKeepsStrictCommaRules(t *testing.T) {
	const input = "{\n // setting\n \"key\":\"example\"\n}"
	n, err := jsonconfig.ParseWithComments(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}

	value := n.Get("key")
	if input[value.Span.Start:value.Span.End] != `"example"` {
		t.Fatal("invalid original span")
	}

	if _, err := jsonconfig.ParseWithComments(t.Context(), `{/* setting */ "key": 1,}`); err == nil {
		t.Fatal("accepted trailing comma in comments-only settings")
	}
}

func TestJSONCRejectsInvalidAndDuplicateDeclarations(t *testing.T) {
	for _, input := range []string{`{"one":1,/* comment */"one":2}`, `[ , ]`, `{,}`, `{"one":/*`, `[1,,]`, `{ "one" /* gap */ "two" }`} {
		t.Run(strings.ReplaceAll(input, "/", "_"), func(t *testing.T) {
			if _, err := jsonconfig.ParseJSONC(t.Context(), input); err == nil {
				t.Fatalf("accepted invalid JSONC %q", input)
			}
		})
	}
}
