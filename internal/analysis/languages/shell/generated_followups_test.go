package shell_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestGeneratedShellRecoversHeredocOnStdin(t *testing.T) {
	const body = "printf example\n"
	for _, tc := range []struct{ name, text, want, original string }{
		{"direct", "bash <<'END'\n" + body + "END\n", body, body},
		{"direct with stdout redirect", "bash <<'END' >log\n" + body + "END\n", body, body},
		{"explicit stdin and arguments", "/bin/sh -s -- arg <<'END'\n" + body + "END\n", body, body},
		{"identity pipeline", "cat <<'END' | sh\n" + body + "END\n", body, body},
		{"identity pipeline with tabs", "cat <<-'END' | /bin/bash -s\n\t" + body + "\tEND\n", body, body},
		{"parameter expansion", "verb=printf\nsh <<END\n$verb example\nEND\n", body, "$verb example\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != tc.want {
				t.Fatalf("unexpected shell stdin recovery: %+v", got)
			}
			span, err := got.Views[0].Original(source.Span{End: len(tc.want)})
			if err != nil || span.Start != strings.Index(tc.text, tc.original) || span.End-span.Start != len(tc.original) {
				t.Fatalf("body mapped to %+v, want %q at offset %d: %v", span, tc.original, strings.Index(tc.text, tc.original), err)
			}
		})
	}
}

func TestGeneratedShellIgnoresHeredocOutsideProvedStdinExecution(t *testing.T) {
	const body = "\nprintf example\nEND\n"
	for _, tc := range []struct{ name, text string }{
		{"plain data", "cat <<'END'" + body},
		{"different descriptor", "sh 3<<'END'" + body},
		{"syntax check only", "bash -n <<'END'" + body},
		{"command string", "bash -c ':' <<'END'" + body},
		{"script file", "sh existing-script <<'END'" + body},
		{"redirected stdin", "sh <<'END' < input" + body},
		{"shadowed interpreter", "sh() { :; }\nsh <<'END'" + body},
		{"hashed interpreter", "hash -p /usr/bin/true sh\nsh <<'END'" + body},
		{"pipeline producer overrides stdin", "cat <<'END' < input | sh" + body},
		{"pipeline producer overrides stdout", "cat <<'END' > output | sh" + body},
		{"pipeline consumer overrides stdin", "cat <<'END' | sh < input" + body},
		{"pipeline consumer duplicates stdin", "cat <<'END' | sh <&3" + body},
		{"pipeline consumer reads a file", "cat <<'END' | sh existing-script" + body},
		{"pipeline transforms stdin", "cat -n <<'END' | sh" + body},
		{"pipeline mixes stderr", "cat <<'END' |& sh" + body},
		{"shadowed pipeline producer", "cat() { :; }\ncat <<'END' | sh" + body},
		{"shadowed pipeline consumer", "sh() { :; }\ncat <<'END' | sh" + body},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Views) != 0 || len(got.Executions) != 0 {
				t.Fatalf("unproved stdin became executable shell input: %+v", got)
			}
		})
	}
}

func TestGeneratedShellUnresolvedStdinReportsOriginalLocation(t *testing.T) {
	const prefix = "# setup\n"
	const text = prefix + "sh <<END\n$value\nEND\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != document.GeneratedShellUnrecovered || len(got.Views) != 0 || len(got.Issues) != 1 {
		t.Fatalf("unexpected recovery for unresolved stdin: %+v", got)
	}
	if issue := got.Issues[0]; issue.At != len(prefix) || issue.Reason != document.GeneratedShellExpansion {
		t.Fatalf("incorrect stdin diagnostic: %+v", issue)
	}
}

func TestGeneratedShellExecutionTracksRenamedFile(t *testing.T) {
	const body = "printf current\n"
	const header = "cat > staging <<'END'"
	const write = header + "\n" + body + "END\n"
	const prior = "cat > live <<'OLD'\nprintf obsolete\nOLD\n"
	for _, tc := range []struct {
		name, text, use string
		moves           []string
	}{
		{"literal move", write + "mv staging live\nbash ./live\n", "bash ./live", []string{"mv staging live"}},
		{"explicit executable and option terminator", write + "/bin/mv -- staging ./live\nsource ./live\n", "source ./live", []string{"/bin/mv -- staging ./live"}},
		{"replacement", prior + write + "mv staging ./live\nsh live\n", "sh live", []string{"mv staging ./live"}},
		{"relative to current directory", "cd build\n" + write + "mv staging live\ncd ..\nbash build/live\n", "bash build/live", []string{"mv staging live"}},
		{"consecutive moves", write + "mv staging intermediate\nmv intermediate live\nsh ./live\n", "sh ./live", []string{"mv staging intermediate", "mv intermediate live"}},
		{"known destination reused by interpreter", "dest=./live\n" + write + "mv staging \"$dest\"\nsh \"$dest\"\n", `sh "$dest"`, []string{`mv staging "$dest"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != body || len(got.Executions) != 1 || got.ExecutionLimited {
				t.Fatalf("unexpected recovery after move: %+v", got)
			}
			link := got.Executions[0]
			if tc.text[link.Write.Start:link.Write.End] != header ||
				tc.text[link.Body.Start:link.Body.End] != body ||
				tc.text[link.Use.Start:link.Use.End] != tc.use {
				t.Fatalf("move lost original write, body, or use: %+v", link)
			}
			for i, want := range tc.moves {
				span := link.Transforms[i]
				if got := tc.text[span.Start:span.End]; got != want {
					t.Fatalf("move trace step %d = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestGeneratedShellPromotesCandidateMovedToShellPath(t *testing.T) {
	const body = "printf example\n"
	const write = "cat >staging <<'END'\n" + body + "END\n"
	const moved = write + "mv staging setup.sh\n"
	for _, tc := range []struct {
		name, text string
		links      int
	}{
		{"no invocation required", moved, 0},
		{"later invocation uses the same projection", moved + "sh ./setup.sh\n", 1},
		{"later append stays confirmed", moved + "cat >>setup.sh <<'END'\nEND\nsh ./setup.sh\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != 0 || len(got.Views) != 1 || len(got.Executions) != tc.links || got.Views[0].Text() != body {
				t.Fatalf("unexpected recovery after move to shell path: %+v", got)
			}
			span, err := got.Views[0].Original(source.Span{End: len(body)})
			if err != nil || tc.text[span.Start:span.End] != body {
				t.Fatalf("body no longer points to its heredoc: %v, %v", span, err)
			}
		})
	}
}

func TestGeneratedShellExecutionDiscardsAmbiguousMoves(t *testing.T) {
	const write = "cat > staging <<'END'\nprintf current\nEND\n"
	const prior = "cat > live <<'OLD'\nprintf obsolete\nOLD\n"
	for _, tc := range []struct{ name, text string }{
		{"stale source", write + "mv staging live\nsh ./staging\n"},
		{"unknown source overwrites destination", prior + "mv unknown live\nsh ./live\n"},
		{"ordinary write overwrites moved destination", write + "mv staging live\nprintf data > live\nsh ./live\n"},
		{"no-clobber option", prior + write + "mv -n staging live\nsh ./live\n"},
		{"directory operand", write + "mv staging sub/\nsh ./sub\n"},
		{"tracked directory", "cat > sub/marker <<'END'\nmarker\nEND\n" + write + "mv staging sub\nsh ./sub\n"},
		{"destination parent is a tracked file", prior + write + "mv staging live/nested\nsh ./live/nested\n"},
		{"source file cannot contain destination", write + "mv staging staging/nested\nsh ./staging/nested\n"},
		{"dynamic operand", write + "mv staging \"$destination\"\nsh ./live\n"},
		{"shadowed command", "mv() { :; }\n" + write + "mv staging live\nsh ./live\n"},
		{"exec replaces the caller", write + "exec /bin/mv staging live\nsh ./live\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Views) != 0 || len(got.Executions) != 0 {
				t.Fatalf("unproved move confirmed a shell script: %+v", got)
			}
		})
	}
}

func TestGeneratedShellKeepsAppendAndMoveOrder(t *testing.T) {
	const text = "cat >staging <<'ONE'\nprintf first\nONE\nmv staging intermediate\n" +
		"cat >>intermediate <<'TWO'\nprintf second\nTWO\nmv intermediate live\nbash ./live\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf first\nprintf second\n" || len(got.Executions) != 1 {
		t.Fatalf("unexpected deferred move and append recovery: %+v", got)
	}

	for i, want := range []string{"mv staging intermediate", "printf second\n", "mv intermediate live"} {
		span := got.Executions[0].Transforms[i]
		if got := text[span.Start:span.End]; got != want {
			t.Fatalf("step %d = %q, want %q", i, got, want)
		}
	}
}

func TestGeneratedShellJoinsOnlyCommonBranchVersions(t *testing.T) {
	const body = "printf example\n"
	const header = "cat >setup <<'END'"
	const write = header + "\n" + body + "END\n"
	const run = "sh ./setup"
	for _, tc := range []struct {
		name, text string
		link       bool
	}{
		{"both paths preserve original", write + "if test -n x; then :; else printf note; fi\n" + run, true},
		{"implicit else preserves original", write + "if test -n x; then :; fi\n" + run, true},
		{"equal working directory", "cat >sub/setup <<'END'\n" + body + "END\nif test -n x; then cd sub; else cd ./sub; fi\n" + run, true},
		{"same writer function in both branches", "write_setup() {\n" + write + "}\nif test -n x; then write_setup; else write_setup; fi\n" + run, true},
		{"same writer function through elif", "write_setup() {\n" + write + "}\nif test -n x; then write_setup; elif test -n y; then write_setup; else write_setup; fi\n" + run, true},
		{"only one path writes", "if test -n x; then\n" + write + "fi\n" + run, false},
		{"same bytes but different origins", "if test -n x; then\n" + write + "else\n" + write + "fi\n" + run, false},
		{"conditional overwrite", write + "if test -n x; then printf replaced >setup; fi\n" + run, false},
		{"unknown branch effect", write + "if test -n x; then external-command; fi\n" + run, false},
		{"different working directories", write + "if test -n x; then cd sub; fi\n" + run, false},
		{"write in a condition might fail", "if " + write + "then :; fi\n" + run, false},
		{"early function return bypasses write", "prepare() {\nif test -n x; then return; fi\n" + write + "}\nprepare\n" + run, false},
		{"early return and fallthrough preserve write", write + "prepare() {\nif test -n x; then return; fi\n:\n}\nprepare\n" + run, true},
		{"both return branches preserve write", write + "prepare() {\nif test -n x; then return; else return; fi\n}\nprepare\n" + run, true},
		{"all branches return failure before success-only invocation", write + "prepare() {\nif test -n x; then return 1; else return 2; fi\n}\nprepare && " + run, false},
		{"all branches return success before success-only invocation", write + "prepare() {\nif test -n x; then return 0; else return 0; fi\n}\nprepare && " + run, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != 0 || got.ExecutionLimited || (len(got.Executions) == 1) != tc.link {
				t.Fatalf("unexpected branch recovery: %+v", got)
			}
			if tc.link {
				link := got.Executions[0]
				if tc.text[link.Body.Start:link.Body.End] != body || tc.text[link.Use.Start:link.Use.End] != run ||
					link.Write.Start != strings.Index(tc.text, "cat >") {
					t.Fatalf("branch join lost original write, body, or use: %+v", link)
				}
			} else if len(got.Executions) != 0 {
				t.Fatalf("ambiguous branch produced execution links: %+v", got.Executions)
			}
		})
	}
}
