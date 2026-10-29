//nolint:testpackage // Differential tests compare private lexical guards and exact source offsets with their former expressions.
package analyzer

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func FuzzFixedTextGrammars(f *testing.F) {
	cases := []struct {
		old   string
		match func(string) bool
	}{
		{old: `^(?:[^'"]|'[^']*'|"[^"]*")*$`, match: completeQuotes},
		{old: `^[\t ]*:?-+:?[\t ]*$`, match: paddingDelimiter},
		{old: `--(?:index-url|extra-index-url|find-links)|^-(?:i|f) `, match: requirementsSourceFlag},
		{old: `^[#;]`, match: sourceConfigComment},
		{old: `(?:^|\.)[xX*](?:\.|$)`, match: registryVersionWildcard},
	}
	old := make([]*regexp.Regexp, len(cases))
	for i, tc := range cases {
		old[i] = regexp.MustCompile(tc.old)
	}
	breaks := regexp.MustCompile(`\r\n|[\r\n\x{85}\x{2028}\x{2029}]`)
	keyword := regexp.MustCompile(`(?:return|throw|case)$`)
	for _, s := range []string{"", "\n", "\r\n\r\n", "a\r\nb\rc\nd\u0085e\u2028f\u2029g", "\xff\r\n\xc2\x85\xff", `a 'quoted "string"'`, "\"open", ":--:", "\t:-:\t", "python3\nanything", "-i ", "abc--index-url", "#comment", "1.x.3", "ax", "*.x", "~\n", "~/\n", "~anything", "case", "forecast", "some.return"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for i, tc := range cases {
			if got, want := tc.match(s), old[i].MatchString(s); got != want {
				t.Fatalf("%s %q: got %v want %v", tc.old, s, got, want)
			}
		}
		wantKeyword := -1
		if match := keyword.FindStringIndex(s); match != nil {
			wantKeyword = match[0]
		}
		if got := regexpKeywordStart(s); got != wantKeyword {
			t.Fatalf("keyword %q: got %d want %d", s, got, wantKeyword)
		}
		points := breaks.FindAllStringIndex(s, -1)
		want := make([]paddingLine, 0, len(points)+1)
		start := 0
		for _, at := range points {
			want = append(want, paddingLine{text: s[start:at[0]], start: start, end: at[1]})
			start = at[1]
		}
		want = append(want, paddingLine{text: s[start:], start: start, end: len(s)})
		if got := paddingLines(s); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q: got %+v want %+v", s, got, want)
		}
	})
}

func BenchmarkPaddingLines(b *testing.B) {
	text := strings.Repeat("ordinary words\r\n| col | text |\n\t:-:\n", 100)
	old := regexp.MustCompile(`\r\n|[\r\n\x{85}\x{2028}\x{2029}]`)
	b.Run("regexp", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			points := old.FindAllStringIndex(text, -1)
			lines := make([]paddingLine, 0, len(points)+1)
			start := 0
			for _, p := range points {
				lines = append(lines, paddingLine{text: text[start:p[0]], start: start, end: p[1]})
				start = p[1]
			}
			_ = append(lines, paddingLine{text: text[start:], start: start, end: len(text)})
		}
	})
	b.Run("bytes", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = paddingLines(text)
		}
	})
}
