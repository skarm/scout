package configuration

import (
	"regexp"
	"testing"
)

func FuzzRegistryVersionWildcard(f *testing.F) {
	old := regexp.MustCompile(`(?:^|\.)[xX*](?:\.|$)`)
	for _, s := range []string{"", "\n", "\r\n\r\n", "a\r\nb\rc\nd\u0085e\u2028f\u2029g", "\xff\r\n\xc2\x85\xff", `a 'quoted "string"'`, "\"open", ":--:", "\t:-:\t", "python3\nanything", "-i ", "abc--index-url", "#comment", "1.x.3", "ax", "*.x", "~\n", "~/\n", "~anything", "case", "forecast", "some.return"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := registryVersionWildcard(s), old.MatchString(s); got != want {
			t.Fatalf("wildcard %q: got %v want %v", s, got, want)
		}
	})
}
