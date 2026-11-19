//go:build !coreonly && cgo

package scriptsyntax_test

import (
	"testing"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func TestInvalidEscapedIdentifierCannotBecomeParsedSyntax(t *testing.T) {
	for _, name := range []string{"ⸯ", "aⸯb", `\u2e2f`, `\uD800`, `\u{110000}`, `\u0030name`, `bad\u0020name`} {
		for _, lang := range []string{"javascript", "typescript"} {
			if _, err := scriptsyntax.Parse(t.Context(), lang, "const "+name+"=()=>{};"); err == nil {
				t.Errorf("%s accepted invalid identifier %s", lang, name)
			}
		}
	}
}

func TestValidEscapedIdentifiersRetainOriginalCoordinates(t *testing.T) {
	for _, lang := range []string{"javascript", "typescript"} {
		text := `const \u{10400}=1; const a\u200db=2; const \u03c0=3; obj.\u0064efault; class C { #na\u006de=1; }`
		tree, err := scriptsyntax.Parse(t.Context(), lang, text)
		if err != nil || tree.Root == nil || tree.Root.Start != 0 || tree.Root.End != len(text) {
			t.Fatalf("valid Unicode identifiers rejected: %+v %v", tree, err)
		}
	}
}

func TestInvalidEscapedIdentifierAliasesCannotBecomeParsedSyntax(t *testing.T) {
	for _, tc := range []struct{ lang, text string }{
		{"javascript", `\uD800: while(true){break \uD800;}`},
		{"typescript", `type \uD800 = string;`},
		{"typescript", `interface \uD800 {x:string;}`},
		{"typescript", `let x: \uD800;`},
		{"typescript", `class \uD800 {}`},
	} {
		if _, err := scriptsyntax.Parse(t.Context(), tc.lang, tc.text); err == nil {
			t.Errorf("accepted invalid identifier alias: %s", tc.text)
		}
	}
}
