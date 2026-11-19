package scriptsyntax_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func TestIdentifierTextPreservesIdentity(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`fetch`, `fetch`},
		{`fe\u0074ch`, `fetch`},
		{`\u{66}etch`, `fetch`},
		{`\u{000000000000000066}etch`, `fetch`},
		{`π\u0061`, "πa"},
		{`\u{10400}name`, "𐐀name"},
		{`\u{105c0}name`, "𐗀name"},
		{"𐗀\\u0061", "𐗀a"},
		{`a\u200cb`, "a\u200cb"},
		{`a\u0301`, "a\u0301"},
		{`\u00e1`, "á"},
		{`\u0024name`, "$name"},
	} {
		for _, kind := range []string{"identifier", "type_identifier", "statement_identifier", "property_identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"} {
			got, err := scriptsyntax.IdentifierText(kind, tc.raw)
			if err != nil || got != tc.want {
				t.Errorf("%s %q=%q, %v; want %q", kind, tc.raw, got, err, tc.want)
			}
		}
	}
	for _, kind := range []string{"string", "template_string", "comment", "number"} {
		raw := `"fe\\u0074ch"`
		got, err := scriptsyntax.IdentifierText(kind, raw)
		if err != nil || got != raw {
			t.Fatalf("non-identifier rewritten: %q %v", got, err)
		}
	}
}

func TestPrivateIdentifierText(t *testing.T) {
	got, err := scriptsyntax.IdentifierText("private_property_identifier", `#na\u006de`)
	if err != nil || got != "#name" {
		t.Fatalf("private identifier: %q %v", got, err)
	}
	for _, raw := range []string{`#\uD800`, `#\u0030name`, `\u0061`} {
		if _, err := scriptsyntax.IdentifierText("private_property_identifier", raw); err == nil {
			t.Fatalf("invalid private identifier: %q", raw)
		}
	}
}

func TestIdentifierTextRejectsInvalidEscapes(t *testing.T) {
	for _, raw := range []string{"ⸯ", "aⸯb", `\u2e5e`, `a\u2e5e`, `\u`, `\u12`, `\uZZZZ`, `\x61`, `\u{}`, `\u{61`, `\u{110000}`, `\u2e2f`, `a\u2e2f`, `\uD800`, `\uD800\uDC00`, `\u{dfff}`, `\u0030name`, `a\u0020b`, `\u005cu0061`, `a\u{ffffffffffffffffffffffff}`, "a\\u0062\xff"} {
		if got, err := scriptsyntax.IdentifierText("identifier", raw); err == nil || got != "" {
			t.Errorf("accepted invalid identifier %q: %q %v", raw, got, err)
		}
	}
}

func FuzzIdentifierText(f *testing.F) {
	for _, seed := range []string{`plain`, `fe\u0074ch`, `\u{10400}`, `\uD800`, `a\u200cb`, `\u{000000000061}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16384 {
			return
		}
		got, err := scriptsyntax.IdentifierText("identifier", raw)
		if err == nil {
			if strings.Contains(got, `\`) || len(got) > len(raw) {
				t.Fatalf("invalid decoded result %q", got)
			}
			again, e := scriptsyntax.IdentifierText("identifier", got)
			if e != nil || again != got {
				t.Fatal("decoding is not idempotent")
			}
		}
	})
}
