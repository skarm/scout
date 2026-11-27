package main

import (
	"strings"
	"testing"
)

func TestReviewRecognizesAssertionChanges(t *testing.T) {
	const imports = `package scanner
import (
    tt "testing"
    "slices"
    verify "github.com/stretchr/testify/require"
)
`
	for _, tc := range []struct{ name, before, after, category, subject string }{
		{
			"removed part of compound guard",
			`if err != nil || got != want { t.Fatal("old wording") }`,
			`if err != nil { t.Fatalf("new wording: %v", err) }`, "Test assertion removed", "got",
		},
		{
			"weakened equality",
			`if got != want { t.Error("different") }`,
			`if nil == got { t.Error("missing") }`, "Test assertion weakened", "got",
		},
		{
			"weakened length",
			`if !slices.Equal(got, want) { t.FailNow() }`,
			`if len(got) == 0 { t.Fatalf("missing") }`, "Test assertion weakened", "got",
		},
		{
			"length replaces content comparison",
			`if !slices.Equal(got, want) { t.Fatal("different") }`,
			`if len(got) != len(want) { t.Fatal("different length") }`, "Test assertion weakened", "got",
		},
		{
			"testify length replaces value comparison",
			`verify.Equal(t, want, got)`,
			`verify.Len(t, got, len(want))`, "Test assertion weakened", "got",
		},
		{
			"weakened testify",
			`verify.Equalf(t, want, got, "expected %v", want)`,
			`verify.NotEmpty(t, got)`, "Test assertion weakened", "got",
		},
		{
			"weakened exact error",
			`verify.ErrorIs(t, err, want)`,
			`verify.Error(t, err)`, "Test assertion weakened", "err",
		},
		{
			"changed message and formatting",
			`if got!=want { t.Fatalf("different: %v", got) }`,
			`if (got != want) { t.Error("different") }`, "", "",
		},
		{
			"duplicate failure calls for the same guard",
			`if got != want { t.Error("different"); t.FailNow() }`,
			`if got != want { t.Fatal("different") }`, "", "",
		},
		{
			"equally strict refactor",
			`if got != want { t.Error("different") }`,
			`verify.Equal(t, want, got)`, "", "",
		},
		{
			"strengthened assertion",
			`verify.NotNil(t, got)`,
			`verify.Equal(t, want, got)`, "", "",
		},
		{
			"unrelated method with the same name",
			`if got != want { other.Error("different") }`,
			``, "", "",
		},
		{
			"testify call on an auxiliary reporter",
			`verify.Equal(fake, want, got)`,
			``, "", "",
		},
		{
			"else branch assertion",
			`if got == want { t.Log("ok") } else { t.Error("different") }`,
			`if got == nil { t.Error("missing") }`, "Test assertion weakened", "got",
		},
		{
			"an existing coarse assertion cannot replace a removed exact one",
			`verify.NotNil(t, got); verify.Equal(t, want, got)`,
			`verify.NotNil(t, got)`, "Test assertion removed", "got",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := newInventory(), newInventory()
			prefix := imports + `func TestScan(outer *tt.T) { outer.Run("sub", func(t *tt.T) {` + "\n"
			const suffix = "\n}) }\n"
			if err := before.readGoTests("scan_test.go", []byte(prefix+tc.before+suffix)); err != nil {
				t.Fatal(err)
			}
			if err := after.readGoTests("scan_test.go", []byte(prefix+tc.after+suffix)); err != nil {
				t.Fatal(err)
			}

			warnings := compareInventories(before, after)
			if tc.category == "" {
				if len(warnings) != 0 {
					t.Fatalf("unexpected warnings: %+v", warnings)
				}

				return
			}

			if len(warnings) != 1 || warnings[0].category != tc.category || warnings[0].line != 8 ||
				warnings[0].base != (tc.category == "Test assertion removed") ||
				!strings.Contains(warnings[0].detail, `"TestScan/sub"`) || !strings.Contains(warnings[0].detail, `"`+tc.subject+`"`) {
				t.Fatalf("unexpected warnings: %+v", warnings)
			}
		})
	}
}

func TestRemovedTestIsReportedWithoutAssertionDuplicates(t *testing.T) {
	before, after := newInventory(), newInventory()
	const text = "package scanner\nimport \"testing\"\nfunc TestScan(t *testing.T) { if got!=want { t.Fatal() } }\n"
	if err := before.readGoTests("scan_test.go", []byte(text)); err != nil {
		t.Fatal(err)
	}
	if warnings := compareInventories(before, after); len(warnings) != 1 || warnings[0].category != "Test removed from run" {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
}
