package analyzer_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analyzer"
	"github.com/skarm/scout/knowledge"
)

func TestPatternPrefilterNecessaryConditions(t *testing.T) {
	for _, tc := range []struct{ expression, text string }{
		{expression: `(?im)(foo|bar)\s+baz`, text: "BAR\nBAZ"},
		{expression: `(?i)(?:foo)?bar`, text: "BAR"},
		{expression: `(?i)(?:foo|bar)?baz`, text: "BAZ"},
		{expression: `(?i)(foo|)bar`, text: "BAR"},
		{expression: `(?i)(foo|bar)+`, text: "BARfoo"},
		{expression: `(?i)(foo|bar){0,3}baz`, text: "BAZ"},
		{expression: `(?i)(foo|bar){1,3}baz`, text: "BARBAZ"},
		{expression: `(?i)(foo|[a-z])bar`, text: "XBAR"},
		{expression: `(?i)ſystem`, text: "SYSTEM"},
		{expression: `(?i)Key`, text: "KEY"},
		{expression: `(?i)system`, text: "ſyſtem"},
		{expression: `(?i)key`, text: "Key"},
		{expression: `(?i)foo\b`, text: "foo\xff"},
		{expression: `(?:)`, text: ""},
	} {
		assertPrefilterAcceptsMatch(t, tc.expression, tc.text)
	}
}

func TestPatternPrefiltersPreserveCatalogExamples(t *testing.T) {
	for _, family := range analyzer.PatternFamiliesForTest() {
		expressions := append([]string(nil), family.Expressions...)
		for _, extra := range knowledge.Patterns(family.ID) {
			expressions = append(expressions, extra.Expression)
		}
		for _, expression := range expressions {
			expression = "(?im)" + expression
			for _, other := range analyzer.PatternFamiliesForTest() {
				for _, text := range []string{other.Example, strings.ToUpper(other.Example), "prefix\n" + other.Example + "\nsuffix"} {
					assertPrefilterAcceptsMatch(t, expression, text)
				}
			}
		}
	}
}

func FuzzPatternPrefilter(f *testing.F) {
	for _, family := range analyzer.PatternFamiliesForTest() {
		for _, expression := range family.Expressions {
			f.Add("(?im)"+expression, family.Example)
		}
	}
	f.Fuzz(func(t *testing.T, expression, text string) {
		if len(expression) > 256 || len(text) > 2048 {
			return
		}
		if _, err := regexp.Compile(expression); err != nil {
			return
		}
		assertPrefilterAcceptsMatch(t, expression, text)
	})
}

func BenchmarkPatternCatalog(b *testing.B) {
	b.ReportAllocs()
	familyCount := len(analyzer.PatternFamiliesForTest())
	for b.Loop() {
		if len(analyzer.PatternRules()) != familyCount {
			b.Fatal("incomplete pattern catalog")
		}
	}
}

func TestPatternCatalogDoesNotShareRegistrySlice(t *testing.T) {
	first := analyzer.PatternRules()
	want := first[0].Rule().ID
	first[0] = nil
	if got := analyzer.PatternRules()[0].Rule().ID; got != want {
		t.Fatalf("caller changed compiled catalog: %s", got)
	}
}

func assertPrefilterAcceptsMatch(t testing.TB, expression, text string) {
	t.Helper()
	p, err := regexp.Compile(expression)
	if err != nil {
		t.Fatal(err)
	}
	if p.MatchString(text) && !analyzer.PatternPrefilterAllowsForTest(expression, text) {
		t.Fatalf("prefilter rejected RE2 match: %q on %q", expression, text)
	}
}
