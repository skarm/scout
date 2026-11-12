package shell_test

import (
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
)

func TestGeneratedShellWriteGaps(t *testing.T) {
	const (
		dynamic     = document.GeneratedShellDynamicPath
		appendGap   = document.GeneratedShellAppend
		unsupported = document.GeneratedShellUnrecovered
	)
	for _, tc := range []struct {
		name, header string
		gaps         document.GeneratedShellGaps
	}{
		{"unknown basename", `cat >"${name}.sh" <<'END'`, dynamic},
		{"unknown directory", `tee "$dir/helper.sh" <<'END'`, dynamic},
		{"split extension", `cat >"${name}"."s"h <<'END'`, dynamic},
		{"command substitution in path", `cat >"$(printf name).sh" <<'END'`, dynamic},
		{"glob", `cat >*.sh <<'END'`, dynamic},
		{"known extension variable", "ext=.sh\n" + `tee "$dir/helper$ext" <<'END'`, dynamic},
		{"unquoted known shell path", "name=helper.sh\n" + `cat >$name <<'END'`, dynamic},
		{"runtime sibling of known script", `tee helper.sh "$other" <<'END'`, dynamic},
		{"runtime stdout alongside known script", `tee helper.sh >"$other" <<'END'`, dynamic},
		{"redirect append", `cat >>helper.sh <<'END'`, appendGap},
		{"redirect filename starts with dash", `cat >>-helper.sh <<'END'`, appendGap},
		{"explicit stdout append", `command -- /bin/cat -- - 1>>./helper.sh 0<<'END'`, appendGap},
		{"combined stdout and stderr append", `cat &>>helper.sh <<-'END'`, appendGap},
		{"tee stdout append", `tee data.txt >>helper.sh <<'END'`, appendGap},
		{"tee short append option", `tee -a helper.sh <<'END'`, appendGap},
		{"tee long append option", `command -p -- /usr/bin/tee --append -- helper.sh <<'END'`, appendGap},
		{"tee GNU long append abbreviation", `tee --app --output-error=warn helper.sh <<'END'`, appendGap},
		{"tee filename starts with dash after terminator", `tee -a -- -helper.sh <<'END'`, appendGap},
		{"tee combined options after file", `tee helper.sh -ia <<'END'`, appendGap},
		{"known path in append mode", "out=helper.sh\n" + `tee -a "$out" <<'END'`, appendGap},
		{"tee file survives redirected stdout", `tee -a helper.sh >data.txt <<'END'`, appendGap},
		{"runtime append path", `cat >>"${name}.sh" <<'END'`, dynamic | appendGap},
		{"tee runtime append path", `tee --append "$dir/helper.sh" <<'END'`, dynamic | appendGap},
		{"append through copied stdout", `cat 3>>helper.sh >&3 3>data.txt <<'END'`, appendGap},
		{"stdout copied to itself with move syntax", `cat >>helper.sh 1>&1- <<'END'`, appendGap},
		{"append through copied stdin", `cat 3<<'END' <&3 >>helper.sh`, appendGap},
		{"last stdin is a heredoc", `cat <data.txt <<'END' >>helper.sh`, appendGap},
		{"pipeline uses explicit heredoc stdin", `printf data | cat >>helper.sh <<'END'`, appendGap},
		{"pipeline retains known destination in first command", "out=helper.sh\n" + `cat >>"$out" <<'END' | cat`, appendGap},
		{"pipeline retains known destination in last command", "out=helper.sh\n" + `printf data | tee -a "$out" <<'END'`, appendGap},
		{"pipeline stage cannot change sibling destination", "out=data.txt\n" + `out=helper.sh | cat >>"$out" <<'END'`, 0},
		{"conditional command retains its incoming destination", "out=helper.sh\n" + `cat >>"$out" <<'END' && :`, appendGap},
		{"merged stderr pipeline", `cat >helper.sh <<'END' |& cat`, unsupported},
		{"explicit stdout with combined redirect syntax", `cat 1>&helper.sh <<'END'`, unsupported},
		{"cat transformation", `cat -n >helper.sh <<'END'`, unsupported},
		{"cat long transformation option", `cat --show-all >>helper.sh <<'END'`, appendGap},
		{"cat explicit stdin device", `cat /dev/stdin >>helper.sh <<'END'`, appendGap},
		{"cat reads stdin and a file", `cat -- data.txt - >helper.sh <<'END'`, unsupported},
		{"cat reads stdin and a dynamic file", `cat "$input" - >>helper.sh <<'END'`, appendGap},
		{"BSD cat reads stdin before a late help filename", `cat - --help >>helper.sh <<'END'`, appendGap},
		{"cat help option before operands ignores input", `cat --help - >>helper.sh <<'END'`, 0},
		{"tee data append with script on stdout", `tee -a data.txt >helper.sh <<'END'`, unsupported},
		{"tee append token after option terminator", `tee -- -a helper.sh <<'END'`, unsupported},
		{"static data destination", `cat >>data.txt <<'END'`, 0},
		{"dynamic data destination", `tee -a "$dir/data.txt" <<'END'`, 0},
		{"no evidence of shell extension", `cat >>"$output" <<'END'`, 0},
		{"case-sensitive extension", `cat >>"$dir/helper.SH" <<'END'`, 0},
		{"static absolute destination", `tee -a /tmp/helper.sh <<'END'`, 0},
		{"dynamic absolute destination", `tee -a "/tmp/${name}.sh" <<'END'`, 0},
		{"static traversal destination", `cat >>../helper.sh <<'END'`, 0},
		{"dynamic traversal destination", `cat >>"../${name}.sh" <<'END'`, 0},
		{"split parent path prefix", `cat >>'.'"./sub/${name}.sh" <<'END'`, 0},
		{"stdout replaced", `cat >>helper.sh >data.txt <<'END'`, 0},
		{"only stderr appends", `cat 2>>helper.sh <<'END'`, 0},
		{"combined append replaced on stdout", `cat &>>helper.sh >data.txt <<'END'`, 0},
		{"stdout descriptor closed", `cat >>helper.sh >&- <<'END'`, 0},
		{"duplication of a closed descriptor aborts the command", `cat >>helper.sh 4>&- 5>&4 <<'END'`, 0},
		{"filename in explicit stderr descriptor duplication is invalid", `tee -a helper.sh 2>&data.txt <<'END'`, 0},
		{"stdout copied before append descriptor opens", `cat >&3 3>>helper.sh <<'END'`, 0},
		{"stdin replaced", `tee -a helper.sh <<'END' <data.txt`, 0},
		{"stdin closed", `cat >>helper.sh <<'END' <&-`, 0},
		{"heredoc on unused descriptor", `tee -a helper.sh 3<<'END'`, 0},
		{"cat reads file instead", `cat data.txt >>helper.sh <<'END'`, 0},
		{"tee help option before filename ignores input", `tee -a --help helper.sh <<'END'`, 0},
		{"BSD tee treats late help token as a filename", `tee -a helper.sh --help <<'END'`, appendGap},
		{"BSD tee treats late invalid flag as a filename", `tee helper.sh -x <<'END'`, unsupported},
		{"GNU flag followed by an invalid flag has no viable dialect", `tee -p helper.sh -x <<'END'`, 0},
		{"tee short invalid option ignores input", `tee -x -a helper.sh <<'END'`, 0},
		{"tee invalid long option ignores input", `tee --append=bad helper.sh <<'END'`, 0},
		{"tee invalid output-error mode ignores input", `tee --output-error=bad -a helper.sh <<'END'`, 0},
		{"tee does not treat a flag as a filename", `tee -a -helper.sh <<'END'`, 0},
		{"other command", `printf '%s' data >>helper.sh <<'END'`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.header+"\nprintf example\nEND\n")
			if got.Gaps != tc.gaps {
				t.Fatalf("got gaps %b, want %b", got.Gaps, tc.gaps)
			}
			if len(got.Views) != 0 || len(got.Executions) != 0 || got.ExecutionLimited {
				t.Fatalf("unexpected recovery: %+v", got)
			}
		})
	}
}

func TestGeneratedShellOnlyMergesStderrOnItsOwnPipe(t *testing.T) {
	const text = "out=helper.sh\nprintf data |& cat >\"$out\" <<'END'\nprintf example\nEND\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf example\n" {
		t.Fatalf("unrelated stderr pipe affected recovery: %+v", got)
	}
}

func TestGeneratedShellWriteGapsInDeclarationParser(t *testing.T) {
	const text = "for item in a; do\n  tee -a helper.sh <<'END'\nprintf example\nEND\ndone\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != document.GeneratedShellAppend || len(got.Views) != 0 || len(got.Executions) != 0 {
		t.Fatalf("unexpected recovery from loop: %+v", got)
	}
}

func TestGeneratedShellWriteGapsIgnoreEmptyAppend(t *testing.T) {
	got := recoverGeneratedShell(t, "cat >>helper.sh <<'END'\nEND\n")
	if got.Gaps != 0 || len(got.Views) != 0 || len(got.Executions) != 0 {
		t.Fatalf("unexpected recovery from empty append: %+v", got)
	}
}
