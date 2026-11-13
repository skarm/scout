package shell_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestGeneratedShellBindsPositionalArguments(t *testing.T) {
	const definition = "prepare() {\n: \"$1\"\ncat > \"${1}\" <<END\nprintf '%s' '$2' '${10}' '$10'\nEND\n}\n"
	const invocation = "out=helper.sh\nprepare \"$out\" 'some words' 3 4 5 6 7 8 9 ten\nbash helper.sh\n"
	text := definition + invocation
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || len(got.Executions) != 1 {
		t.Fatalf("unexpected positional recovery: %+v", got)
	}
	view := got.Views[0]
	if want := "printf '%s' 'some words' 'ten' 'helper.sh0'\n"; view.Text() != want {
		t.Fatalf("got %q, want %q", view.Text(), want)
	}
	start := strings.Index(view.Text(), "some words")
	span, err := view.Original(source.Span{Start: start, End: start + len("some words")})
	if err != nil || text[span.Start:span.End] != "$2" {
		t.Fatalf("argument mapped to %+v: %v", span, err)
	}
}

func TestGeneratedShellScopesPositionalArguments(t *testing.T) {
	const write = "cat > helper.sh <<END\nprintf '%s' '$1'\nEND\n"
	for _, tc := range []struct {
		name, text, body string
		gap              document.GeneratedShellGaps
	}{
		{"nested call restores caller arguments", "inner() { :; }\nouter() {\ninner other\n" + write + "}\nouter first\n", "printf '%s' 'first'\n", 0},
		{"quoted argument forwarded to nested call", "inner() {\n" + write + "}\nouter() { inner \"$1\"; }\nouter first\n", "printf '%s' 'first'\n", 0},
		{"shift invalidates arguments", "prepare() {\nshift\n" + write + "}\nprepare first second\n", "", document.GeneratedShellUnrecovered},
		{"possible set invalidates arguments", "prepare() {\nif check; then set -- other; fi\n" + write + "}\nprepare first\n", "", document.GeneratedShellUnrecovered},
		{"uncalled function has no positional binding", "prepare() {\n" + write + "}\n", "", document.GeneratedShellUnrecovered},
		{"subshell cannot change outer arguments", "prepare() {\n( shift )\n" + write + "}\nprepare first second\n", "printf '%s' 'first'\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != tc.gap || (tc.body == "" && len(got.Views) != 0) || (tc.body != "" && len(got.Views) != 1) {
				t.Fatalf("unexpected recovery: %+v", got)
			}
			if tc.body != "" && got.Views[0].Text() != tc.body {
				t.Fatalf("got %q, want %q", got.Views[0].Text(), tc.body)
			}
		})
	}
}

func TestGeneratedShellLinksAcrossFunctionCalls(t *testing.T) {
	const write = "cat > helper.sh <<'END'\nprintf first\nEND\n"
	const use = "bash helper.sh"
	for _, tc := range []struct {
		name, text string
		linked     bool
	}{
		{"callee writes caller executes", "prepare() {\n" + write + "}\nprepare\n" + use + "\n", true},
		{"caller writes callee executes", "run() { " + use + "; }\n" + write + "run\n", true},
		{"callee changes cwd and returns", "prepare() {\ncd sub\n" + write + "return\n}\nprepare\n" + use + "\n", true},
		{"successful return reaches next and-list command", "prepare() {\n" + write + "return 0\n}\nprepare && " + use + "\n", true},
		{"failed return cannot reach next and-list command", "prepare() {\n" + write + "return 1\n}\nprepare && " + use + "\n", false},
		{"failed return still permits an independent command", "prepare() {\n" + write + "return 1\n}\nprepare\n" + use + "\n", true},
		{"callee starts in caller cwd", "prepare() {\ncd sub\n" + write + "}\ncd parent\nprepare\ncd ../..\nbash parent/sub/helper.sh\n", true},
		{"callee overwrites tracked file", "prepare() { printf changed >helper.sh; }\n" + write + "prepare\n" + use + "\n", false},
		{"function declaration redirect can overwrite at call", "prepare() { :; } >helper.sh\n" + write + "prepare\n" + use + "\n", false},
		{"temporary OLDPWD invalidates previous directory", "prepare() { cd -; }\n" + write + "cd sub\nOLDPWD=/elsewhere prepare\n" + use + "\n", false},
		{"callee contains opaque effects", "prepare() { eval \"$action\"; }\n" + write + "prepare\n" + use + "\n", false},
		{"callee writes in background", "prepare() {\n" + write + "}\nprepare &\n" + use + "\n", false},
		{"callee writes conditionally", "prepare() {\nif check; then\n" + write + "fi\n}\nprepare\n" + use + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Views) != 1 || (len(got.Executions) == 1) != tc.linked || len(got.Executions) > 1 {
				t.Fatalf("unexpected cross-call recovery: %+v", got)
			}
			if tc.linked {
				link := got.Executions[0]
				if tc.text[link.Body.Start:link.Body.End] != "printf first\n" || !strings.HasPrefix(tc.text[link.Use.Start:link.Use.End], "bash ") {
					t.Fatalf("link has incorrect source ranges: %+v", link)
				}
			}
		})
	}
}

func TestGeneratedShellReconstructsAppendChain(t *testing.T) {
	const suffix = "cat >>helper.sh <<'END'\nprintf second\nEND\n"
	const initial = "cat >helper.sh <<'END'\nprintf first\nEND\n"
	const last = "tee -a -- helper.sh >/dev/null <<'END'\nprintf third\nEND\n"
	text := "extend() {\n" + suffix + "}\n" + initial + "extend\n" + last + "bash helper.sh\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 3 || len(got.Executions) != 1 {
		t.Fatalf("unexpected append chain: %+v", got)
	}
	view := got.Views[2]
	if view.Text() != "printf first\nprintf second\nprintf third\n" {
		t.Fatalf("wrong append order: %q", view.Text())
	}
	for i, body := range []string{"printf second\n", "printf third\n"} {
		start := strings.Index(view.Text(), body)
		at, err := view.Original(source.Span{Start: start, End: start + len(body)})
		if err != nil || text[at.Start:at.End] != body || got.Executions[0].Transforms[i] != at {
			t.Fatalf("appended body %q mapped to %+v: %v", body, at, err)
		}
	}
	all, err := view.Original(source.Span{End: len(view.Text())})
	if err != nil || all.Start != strings.Index(text, "printf second") || all.End != strings.Index(text, "printf third")+len("printf third\n") {
		t.Fatalf("non-monotonic source bounds: %+v (%v)", all, err)
	}
}

func TestGeneratedShellAppendsToAnEmptyOverwrite(t *testing.T) {
	const text = "cat >helper.sh <<'END'\nEND\ntee >>helper.sh <<'END'\nprintf first\nEND\nbash helper.sh\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf first\n" || len(got.Executions) != 1 {
		t.Fatalf("unexpected recovery after an empty overwrite: %+v", got)
	}
}

func TestGeneratedShellReconstructsOnlyKnownAppendTargets(t *testing.T) {
	const first = "cat >first.sh <<'END'\nprintf first\nEND\n"
	const other = "cat >other.sh <<'END'\nprintf other\nEND\n"
	const appendToBoth = "tee -a first.sh other.sh <<'END'\nprintf tail\nEND\n"
	for _, tc := range []struct {
		name, prefix string
		views        int
		gap          document.GeneratedShellGaps
	}{
		{"both known", first + other, 4, 0},
		{"one unknown", first, 2, document.GeneratedShellAppend},
		{"intervening overwrite", first + "printf changed >first.sh\n" + other, 3, document.GeneratedShellAppend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.prefix+appendToBoth)
			if got.Gaps != tc.gap || len(got.Views) != tc.views || !strings.HasSuffix(got.Views[tc.views-1].Text(), "printf tail\n") {
				t.Fatalf("unexpected multi-target append: %+v", got)
			}
		})
	}
}

func TestGeneratedShellAppendRecoveryOutlivesTraceBudget(t *testing.T) {
	const initial = "cat >helper.sh <<'END'\nprintf first\nEND\n"
	const suffix = "cat >>helper.sh <<'END'\nprintf tail\nEND\n"
	count := document.MaxGeneratedShellTransforms + 1
	got := recoverGeneratedShell(t, initial+strings.Repeat(suffix, count)+"bash helper.sh\n")
	if got.Gaps != 0 || len(got.Views) != count+1 || got.Views[count].Text() != "printf first\n"+strings.Repeat("printf tail\n", count) ||
		len(got.Executions) != 0 || !got.ExecutionLimited {
		t.Fatalf("append recovery and evidence budget conflated: %+v", got)
	}
}
