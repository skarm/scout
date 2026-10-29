package textmatch_test

import (
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/skarm/scout/internal/textmatch"
)

func FuzzASCIIGrammars(f *testing.F) {
	specs := []struct {
		name, old string
		match     func(string) bool
	}{
		{
			name:  "identifier",
			old:   `^[A-Za-z_][A-Za-z0-9_]{0,127}$`,
			match: func(s string) bool { return textmatch.Identifier(s, 128) },
		},
		{
			name:  "repository",
			old:   `^[A-Za-z0-9_.-]{1,128}$`,
			match: func(s string) bool { return textmatch.Token(s, 128, "_.-") },
		},
		{
			name:  "vulnerability",
			old:   `^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`,
			match: func(s string) bool { return textmatch.Token(s, 160, "._:-") && textmatch.Alnum(s[0]) },
		},
		{
			name:  "target",
			old:   `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`,
			match: func(s string) bool { return textmatch.Token(s, 64, "_.-") && textmatch.Alnum(s[0]) },
		},
		{
			name:  "package",
			old:   `^[A-Za-z0-9@][A-Za-z0-9@/_.-]{0,255}$`,
			match: func(s string) bool { return textmatch.Token(s, 256, "@/_.-") && (textmatch.Alnum(s[0]) || s[0] == '@') },
		},
		{
			name:  "identity",
			old:   `^[A-Za-z0-9_.:/@-]{1,128}$`,
			match: func(s string) bool { return textmatch.Token(s, 128, "_.:/@-") },
		},
		{
			name:  "access-id",
			old:   `^[A-Za-z0-9]{8,128}$`,
			match: func(s string) bool { return len(s) >= 8 && textmatch.Token(s, 128, "") },
		},
		{name: "digest", old: `^[a-f0-9]{64}$`, match: func(s string) bool { return textmatch.LowerHex(s, 64) }},
		{
			name:  "skill",
			old:   `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`,
			match: func(s string) bool { return textmatch.Slug(s, 64) },
		},
		{
			name:  "plugin",
			old:   `^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$`,
			match: func(s string) bool { return textmatch.Slug(s, 128) },
		},
		{name: "test-name", old: `^Test[A-Za-z0-9_]+$`, match: func(s string) bool {
			return strings.HasPrefix(s, "Test") && len(s) > 4 && textmatch.Identifier(s, len(s))
		}},
		{
			name:  "version",
			old:   `^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`,
			match: textmatch.Version,
		},
		{
			name:  "registry-version",
			old:   `^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`,
			match: func(s string) bool { return textmatch.Version(strings.TrimPrefix(s, "v")) },
		},
		{
			name:  "tool",
			old:   `^[A-Za-z0-9_*.-]+$`,
			match: func(s string) bool { return textmatch.Token(s, len(s), "_*.-") },
		},
	}
	legacy := make([]*regexp.Regexp, len(specs))
	for i, s := range specs {
		legacy[i] = regexp.MustCompile(s.old)
	}
	npm := regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	for _, s := range []string{"", "a", "A", "_", "-", "ab--cd", "Test", "Test1", "1.2.3", "001.02.003-..+---", "1.2.3-rc.1+build", "1.2.3-", "1.2.3+", "1.2.3-pre+foo+bar", "v1.2.3", "@scope/pkg", "\xff", "K", "ſ", "us-east-1"} {
		f.Add(s)
	}
	for _, n := range []int{7, 8, 63, 64, 65, 127, 128, 129, 159, 160, 161, 255, 256, 257} {
		f.Add(strings.Repeat("a", n))
		f.Add(strings.Repeat("0", n))
	}
	f.Fuzz(func(t *testing.T, s string) {
		for i, tc := range specs {
			if got, want := tc.match(s), legacy[i].MatchString(s); got != want {
				t.Fatalf("%s %q: got %v want %v", tc.name, s, got, want)
			}
		}
		valid := semver.IsValid("v" + s)
		if got, want := textmatch.Version(s) && valid, npm.MatchString(s) && valid; got != want {
			t.Fatalf("npm %q: got %v want %v", s, got, want)
		}
	})
}

func BenchmarkIdentifier(b *testing.B) {
	old := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	for _, s := range []string{"agent_skill_mcp_tool_poisoning_metadata", strings.Repeat("a", 128)} {
		b.Run(s[:min(len(s), 12)], func(b *testing.B) {
			b.Run("regexp", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = old.MatchString(s)
				}
			})
			b.Run("bytes", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = textmatch.Identifier(s, 128)
				}
			})
		})
	}
}
