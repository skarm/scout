package filetype_test

import (
	"testing"

	"github.com/skarm/scout/internal/syntax/filetype"
)

func TestSurface(t *testing.T) {
	for _, tc := range []struct{ name, surface string }{{name: "SKILL.md", surface: "instructions"}, {
		name:    "tests/SKILL.md",
		surface: "instructions",
	}, {
		name:    "tests/x.md",
		surface: "tests",
	}, {
		name:    "LICENSE.txt",
		surface: "license",
	}, {
		name:    "a.py",
		surface: "code",
	}, {
		name:    "plugin.json",
		surface: "config",
	}, {
		name:    "README.md",
		surface: "docs",
	}} {
		if got := filetype.Surface(tc.name); got != tc.surface {
			t.Fatalf("%s => %s != %s", tc.name, got, tc.surface)
		}
	}
}
