//nolint:testpackage // Differential oracle exercises private lexical guards after extraction.
package shell

import (
	"regexp"
	"testing"
)

func FuzzShellTextGrammars(f *testing.F) {
	cases := []struct {
		old   string
		match func(string) bool
	}{
		{old: `(?s)^python(?:3.*)?$`, match: pythonModuleCommand},
		{old: `\.(?:extra-)?index-url$`, match: pythonConfigIndexKey},
		{old: `(?s)^(?:\*|/\*|~(?:/.*)?)$`, match: removalBroadTarget},
	}
	old := make([]*regexp.Regexp, len(cases))
	for i, tc := range cases {
		old[i] = regexp.MustCompile(tc.old)
	}
	for _, s := range []string{"", "\n", "\r\n\r\n", "a\r\nb\rc\nd\u0085e\u2028f\u2029g", "\xff\r\n\xc2\x85\xff", `a 'quoted "string"'`, "\"open", ":--:", "\t:-:\t", "python3\nanything", "-i ", "abc--index-url", "#comment", "1.x.3", "ax", "*.x", "~\n", "~/\n", "~anything", "case", "forecast", "some.return"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for i, tc := range cases {
			if got, want := tc.match(s), old[i].MatchString(s); got != want {
				t.Fatalf("%s %q: got %v want %v", tc.old, s, got, want)
			}
		}
	})
}
