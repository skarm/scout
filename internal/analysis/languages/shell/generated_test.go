package shell_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestGeneratedShellWriterAdmission(t *testing.T) {
	const body = "printf '%s' π\n"
	for _, tc := range []struct {
		name, header string
		accepted     bool
	}{
		{"cat writes stdin", "cat -- - 0<<'END' 1>|./lib/helper.sh", true},
		{"tee writes quoted path", "tee -- 'local scripts/helper.sh' <<'END'", true},
		{"tee discards stdout", "tee helper.sh <<'END' >'/dev/null'", true},
		{"path glob", "cat > *.sh <<'END'", false},
		{"absolute path", "tee /tmp/helper.sh <<'END'", false},
		{"drive path", "tee 'C:\\temp\\helper.sh' <<'END'", false},
		{"dot dot", "cat > sub/../helper.sh <<'END'", false},
		{"tee appends", "tee -a helper.sh <<'END'", false},
		{"tee has multiple destinations", "tee helper.sh other.sh <<'END'", true},
		{"stderr", "cat <<'END' 2>helper.sh", false},
		{"second stdout redirect", "cat <<'END' >helper.sh >/dev/null", false},
		{"second stdin redirect", "cat <<'END' >helper.sh <data", false},
		{"pipeline with explicit stdin", "printf x | cat >helper.sh <<'END'", true},
		{"pipeline that merges stderr", "cat >helper.sh <<'END' |& cat", false},
		{"nonwriter", "printf '%s' >helper.sh <<'END'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.header + "\n" + body + "END\n"
			views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, text))
			if limited || (len(views) == 1) != tc.accepted || len(views) > 1 {
				t.Fatalf("got %d views and limited=%t, want accepted=%t without a gap", len(views), limited, tc.accepted)
			}
			if !tc.accepted {
				return
			}
			start := len(tc.header) + 1
			span, err := views[0].Original(source.Span{End: len(views[0].Text())})
			if views[0].Text() != body || err != nil || span != (source.Span{Start: start, End: start + len(body)}) {
				t.Fatalf("got script %q with span %+v (%v)", views[0].Text(), span, err)
			}
		})
	}
}

func TestGeneratedShellWriterAliases(t *testing.T) {
	const body = "echo recovered\n"
	const write = " > helper.sh <<'END'\n" + body + "END\n"
	for _, tc := range []struct {
		name, prefix, writer string
		shadowed             bool
	}{
		{"builtin alias", "builtin alias cat='head -n 1'\n", "cat", true},
		{"command alias", "command alias cat='head -n 1'\n", "cat", true},
		{"nested wrappers", "command builtin -- alias cat='head -n 1'\n", "cat", true},
		{"command search path", "command -p -- alias cat='head -n 1'\n", "cat", true},
		{"builtin option terminator", "builtin -- alias cat='head -n 1'\n", "cat", true},
		{"query", "command -v alias cat='head -n 1'\nalias cat\n", "cat", false},
		{"quoted writer", "alias cat='head -n 1'\n", "'cat'", false},
		{"different writer", "alias tee='head -n 1'\n", "cat", false},
		{"dynamic alias", "alias \"$definition\"\n", "cat", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, tc.prefix+tc.writer+write))
			if tc.shadowed {
				if len(views) != 0 || !limited {
					t.Fatalf("shadowed writer yielded %d views and limited=%t", len(views), limited)
				}
				return
			}
			if len(views) != 1 || limited || views[0].Text() != body {
				t.Fatalf("unambiguous writer lost: views=%v limited=%t", views, limited)
			}
		})
	}
}

func TestGeneratedShellTracksWriterResolution(t *testing.T) {
	const body = "echo recovered\n"
	const write = " > helper.sh <<'END'\n" + body + "END\n"
	for _, tc := range []struct {
		name, prefix, writer string
		uncertain            bool
	}{
		{"changed path", "PATH=/custom/bin:$PATH\n", "cat", true},
		{"command uses changed path", "export PATH=/custom/bin:$PATH\n", "command cat", true},
		{"path changes inside group", "{ export PATH=/custom/bin:$PATH; }\n", "tee -- helper.sh", true},
		{"standard search path", "PATH=/custom/bin:$PATH\n", "command -p cat", false},
		{"hashed writer", "hash -p /usr/bin/true cat\n", "command -p cat", true},
		{"unrelated hash entry", "hash -p /usr/bin/true other\n", "cat", false},
		{"printf assigns path", "printf -v PATH '%s' /custom/bin\n", "cat", true},
		{"printf only prints path name", "printf '%s' PATH\n", "cat", false},
		{"absolute writer", "PATH=/custom/bin:$PATH\nhash -p /usr/bin/true cat\n", "/bin/cat", false},
		{"called function defines alias", "prepare() { alias cat='head -n 1'; }\nprepare\n", "cat", true},
		{"transitive function changes path", "config() { PATH=/custom/bin:$PATH; }\nprepare() { config; }\nprepare\n", "cat", true},
		{"uncalled function", "prepare() { alias cat='head -n 1'; }\n", "cat", false},
		{"function without lookup effects", "prepare() { printf 'hello'; }\nprepare\n", "cat", false},
		{"isolated path change", "( PATH=/custom/bin:$PATH )\n", "cat", false},
		{"runtime command head", "\"$setup\"\n", "cat", true},
		{"installed debug trap", "trap 'alias cat=true' DEBUG\n:\n", "cat", true},
		{"trap query", "trap -p DEBUG\n", "cat", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, tc.prefix+tc.writer+write))
			if tc.uncertain {
				if len(views) != 0 || !limited {
					t.Fatalf("uncertain writer returned %d views and limited=%t", len(views), limited)
				}
				return
			}
			if limited || len(views) != 1 || views[0].Text() != body {
				t.Fatalf("known writer returned %d views and limited=%t", len(views), limited)
			}
		})
	}
}

func TestGeneratedShellFunctionUsesPossibleCallTimeLookup(t *testing.T) {
	const body = "echo recovered\n"
	const write = " > helper.sh <<'END'\n" + body + "END\n"
	for _, tc := range []struct {
		name, writer, invocation string
		uncertain                bool
	}{
		{"late path change", "cat", "PATH=/custom/bin:$PATH\nprepare\n", true},
		{"late hash override", "command -p cat", "hash -p /usr/bin/true cat\nprepare\n", true},
		{"absolute writer", "/bin/cat", "PATH=/custom/bin:$PATH\nprepare\n", false},
		{"unchanged lookup", "cat", "prepare\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "prepare() {\n" + tc.writer + write + "}\n" + tc.invocation
			views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, text))
			if tc.uncertain {
				if !limited || len(views) != 0 {
					t.Fatalf("unverified function write yielded %d views, limited=%t", len(views), limited)
				}
				return
			}
			if limited || len(views) != 1 || views[0].Text() != body {
				t.Fatalf("known function writer lost: %d views, limited=%t", len(views), limited)
			}
		})
	}
}

func TestGeneratedShellRejectsBindingsChangedByFunctionsOrTraps(t *testing.T) {
	const write = "verb=eval\n/bin/cat > helper.sh <<END\n$verb 'printf ok'\nEND\n"
	for _, tc := range []struct{ name, prefix string }{
		{"typed global assignment", "prepare() { declare -gu verb; }\nprepare\n"},
		{"debug trap", "trap 'verb=echo' DEBUG\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, tc.prefix+write))
			if !limited || len(views) != 0 {
				t.Fatalf("runtime binding yielded %d views and limited=%t", len(views), limited)
			}
		})
	}
}

func TestGeneratedShellOperationQuotaRetainsPrefix(t *testing.T) {
	const first = "cat > first.sh <<'END'\necho first\nEND\n"
	const second = "cat > second.sh <<'END'\necho second\nEND\n"
	doc := generatedShellDocument(t, first+second)
	for _, tc := range []struct {
		name  string
		quota uint64
		want  []string
	}{
		{"none", 0, nil},
		{"prefix", 1, []string{"echo first\n"}},
		{"exact", 2, []string{"echo first\n", "echo second\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := analysisbudget.WithLimit(t.Context(), tc.quota)
			views, limited := shell.GeneratedScripts(ctx, doc)
			if len(views) != len(tc.want) || limited != (tc.quota < 2) || analysisbudget.Used(ctx) != tc.quota {
				t.Fatalf("got %d views, limited=%t, used=%d", len(views), limited, analysisbudget.Used(ctx))
			}
			for i, want := range tc.want {
				if views[i].Text() != want {
					t.Fatalf("view %d = %q, want %q", i, views[i].Text(), want)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if views, limited := shell.GeneratedScripts(ctx, doc); len(views) != 0 || !limited {
		t.Fatalf("cancelled recovery returned %d views and limited=%t", len(views), limited)
	}
}

func TestGeneratedShellProjectionLimits(t *testing.T) {
	for _, tc := range []struct {
		name, operator, raw, want string
	}{
		{"escapes", "<<END", "\\$", "$"},
		{"tab-separated lines", "<<-'END'", "\t:\n", ":\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, extra := range []int{0, 1} {
				count := document.MaxSourceSegments + extra
				suffix := "\n"
				if strings.HasSuffix(tc.raw, "\n") {
					suffix = ""
				}
				text := "cat > helper.sh " + tc.operator + "\n" + strings.Repeat(tc.raw, count) + suffix + "END\n"
				views, limited := shell.GeneratedScripts(t.Context(), generatedShellDocument(t, text))
				if extra != 0 {
					if !limited || len(views) != 0 {
						t.Fatalf("overflow published %d views with limited=%t", len(views), limited)
					}
					continue
				}
				if limited || len(views) != 1 || views[0].Text() != strings.Repeat(tc.want, count)+suffix {
					t.Fatalf("exact limit was not retained: %d views, limited=%t", len(views), limited)
				}
			}
		})
	}
}

func TestGeneratedShellRetainsUnitsUpToRegionLimit(t *testing.T) {
	const write = "cat > helper.sh <<'END'\necho retained\nEND\n"
	doc := generatedShellDocument(t, strings.Repeat(write, document.MaxRegions))
	views, limited := shell.GeneratedScripts(t.Context(), doc)
	if !limited || len(views) != document.MaxRegions-1 {
		t.Fatalf("expected parent unit and capped prefix: %d views, limited=%t", len(views), limited)
	}
	last := views[len(views)-1]
	span, err := last.Original(source.Span{End: len(last.Text())})
	start := (document.MaxRegions-2)*len(write) + strings.Index(write, "echo retained")
	if err != nil || span != (source.Span{Start: start, End: start + len("echo retained\n")}) {
		t.Fatalf("last admitted view lost its distinct origin: %+v (%v)", span, err)
	}
}

func TestGeneratedShellByteBudgetKeepsSmallProjections(t *testing.T) {
	const body = "echo first\n"
	const input = "cat > first.sh <<'END'\n" + body + "END\n" +
		"cat > oversized.sh <<'END'\necho oversized\nEND\n" +
		"cat > small.sh <<'END'\n:\nEND\n"
	units := generatedShellDocument(t, input).Units()
	views, limited := shell.GeneratedScriptsIn(t.Context(), units, document.MaxRegions, len(body)+len(":\n"))
	if !limited || len(views) != 2 || views[0].Text() != body || views[1].Text() != ":\n" {
		t.Fatalf("projection budget discarded valid siblings or retained oversized output: %d views, limited=%t", len(views), limited)
	}
}

func generatedShellDocument(t *testing.T, text string) document.File {
	t.Helper()
	return document.Prepare(t.Context(), artifact.NewFile("setup.sh", []byte(text), false))
}
