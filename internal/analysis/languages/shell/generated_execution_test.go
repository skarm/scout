package shell_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
)

func TestGeneratedShellExecutionTracksPathAndLatestWrite(t *testing.T) {
	const body = "echo first\n"
	const write = "cat > helper.sh <<'END'\n" + body + "END\n"
	const subWrite = "cat > sub/helper.sh <<'END'\n" + body + "END\n"
	const replacement = "tee -- helper.sh sibling.sh <<'NEXT'\necho second\nNEXT\n"
	for _, tc := range []struct {
		name, text, header, body, use string
	}{
		{"source", write + "source ./helper.sh\n", "cat > helper.sh <<'END'", body, "source ./helper.sh"},
		{"dot", write + ". -- ./helper.sh\n", "cat > helper.sh <<'END'", body, ". -- ./helper.sh"},
		{"interpreter", write + "/bin/bash -eu -- helper.sh\n", "cat > helper.sh <<'END'", body, "/bin/bash -eu -- helper.sh"},
		{"direct and chmod", write + "chmod +x ./helper.sh\n./helper.sh\n", "cat > helper.sh <<'END'", body, "./helper.sh"},
		{"exec", write + "exec -- ./helper.sh\n", "cat > helper.sh <<'END'", body, "exec -- ./helper.sh"},
		{"write then cd", subWrite + "cd -- sub\nbash ./helper.sh\n", "cat > sub/helper.sh <<'END'", body, "bash ./helper.sh"},
		{"cd then write then parent", "cd sub\n" + write + "cd ..\nbash sub/helper.sh\n", "cat > helper.sh <<'END'", body, "bash sub/helper.sh"},
		{"cd back to tracked directory", "cd sub\n" + write + "cd ../other\ncd -\nbash ./helper.sh\n", "cat > helper.sh <<'END'", body, "bash ./helper.sh"},
		{"unconditional group preserves cwd", subWrite + "{ cd sub; }\nbash ./helper.sh\n", "cat > sub/helper.sh <<'END'", body, "bash ./helper.sh"},
		{"write inside group", "{\n" + write + "}\nbash helper.sh\n", "cat > helper.sh <<'END'", body, "bash helper.sh"},
		{"absolute cwd", "cd /workspace\n" + write + "bash /workspace/helper.sh\n", "cat > helper.sh <<'END'", body, "bash /workspace/helper.sh"},
		{
			"success chain", "cd ./sub && cat > helper.sh <<'END' && bash ./helper.sh\n" + body + "END\n",
			"cat > helper.sh <<'END'", body, "bash ./helper.sh",
		},
		{"unrelated write", write + "printf '%s' ignored > different.sh\nbash helper.sh\n", "cat > helper.sh <<'END'", body, "bash helper.sh"},
		{"recovered overwrite", write + replacement + "bash helper.sh\n", "tee -- helper.sh sibling.sh <<'NEXT'", "echo second\n", "bash helper.sh"},
		{"tee sibling", write + replacement + "bash sibling.sh\n", "tee -- helper.sh sibling.sh <<'NEXT'", "echo second\n", "bash sibling.sh"},
		{"explicit cd bypasses CDPATH", "CDPATH=/elsewhere\n" + subWrite + "cd ./sub\nbash ./helper.sh\n", "cat > sub/helper.sh <<'END'", body, "bash ./helper.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Executions) != 1 || got.ExecutionLimited {
				t.Fatalf("got %d links and limited=%t", len(got.Executions), got.ExecutionLimited)
			}
			link := got.Executions[0]
			if got := tc.text[link.Write.Start:link.Write.End]; !strings.HasPrefix(got, tc.header) {
				t.Fatalf("write evidence %q, want header %q", got, tc.header)
			}
			if got := tc.text[link.Body.Start:link.Body.End]; got != tc.body {
				t.Fatalf("body evidence %q, want %q", got, tc.body)
			}
			if got := tc.text[link.Use.Start:link.Use.End]; got != tc.use {
				t.Fatalf("use evidence %q, want %q", got, tc.use)
			}
		})
	}
}

func TestGeneratedShellExecutionDiscardsUnprovedLinks(t *testing.T) {
	const write = "cat > helper.sh <<'END'\necho first\nEND\n"
	for _, tc := range []struct{ name, text string }{
		{"ordinary overwrite", write + "echo replacement > helper.sh\nbash helper.sh\n"},
		{"append", write + "echo extra >> helper.sh\nbash helper.sh\n"},
		{"heredoc append", write + "cat >> helper.sh <<'END'\necho second\nEND\nbash helper.sh\n"},
		{"tee append", write + "tee -a helper.sh <<'END'\necho second\nEND\nbash helper.sh\n"},
		{"dynamic heredoc overwrite", write + "cat > \"$name.sh\" <<'END'\necho second\nEND\nbash helper.sh\n"},
		{"truncated before source", write + "source ./helper.sh >helper.sh\n"},
		{"dynamic overwrite", write + "echo changed > \"$output\"\nbash helper.sh\n"},
		{"substitution overwrite", write + "x=$(echo changed >helper.sh)\nbash helper.sh\n"},
		{"file mutation by unknown command", write + "custom-script\nbash helper.sh\n"},
		{"other directory", write + "cd ./elsewhere\nbash helper.sh\n"},
		{"dynamic directory", write + "cd \"$destination\"\nbash helper.sh\n"},
		{"OLDPWD reassigned", "cd sub\n" + write + "cd ../other\nOLDPWD=/elsewhere\ncd -\nbash ./helper.sh\n"},
		{"subshell cannot supply file proof outside", "(\n" + write + ")\nbash helper.sh\n"},
		{"CDPATH search", "CDPATH=/elsewhere\ncat > sub/helper.sh <<'END'\necho first\nEND\ncd sub\nbash helper.sh\n"},
		{"source search path", write + "source helper.sh\n"},
		{"bare executable lookup", write + "helper.sh\n"},
		{"syntax-only shell", write + "bash -n helper.sh\n"},
		{"shell command string", write + "bash -c helper.sh\n"},
		{"exec does not invoke source builtin", write + "exec source ./helper.sh\n"},
		{"shadowed consumer", "bash() { echo other; }\n" + write + "bash helper.sh\n"},
		{"hashed interpreter", "hash -p /usr/bin/true bash\n" + write + "bash helper.sh\n"},
		{"background write", "cat > helper.sh <<'END' &\necho first\nEND\nbash helper.sh\n"},
		{"negated success", "! cat > helper.sh <<'END' && bash helper.sh\necho first\nEND\n"},
		{"failure branch", "cat > helper.sh <<'END' || bash helper.sh\necho first\nEND\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Views) == 0 {
				t.Fatal("fixture lost the statically recovered body")
			}
			if len(got.Executions) != 0 {
				t.Fatalf("unproved execution was linked: %+v", got.Executions)
			}
		})
	}
}

func TestGeneratedShellExecutionRetainsWritesWhenLinkQuotaEnds(t *testing.T) {
	const text = "cat > helper.sh <<'END'\necho first\nEND\nbash helper.sh\n"
	ctx := analysisbudget.WithLimit(t.Context(), 1)
	got := shell.RecoverGeneratedShellIn(ctx, generatedShellDocument(t, text).Units(), document.MaxRegions, document.MaxScanBytes)
	if len(got.Views) != 1 || len(got.Executions) != 0 || got.Gaps != 0 || !got.ExecutionLimited {
		t.Fatalf("recovery and link quotas conflated: %+v", got)
	}
}

func recoverGeneratedShell(t *testing.T, text string) shell.GeneratedShellRecovery {
	t.Helper()
	doc := generatedShellDocument(t, text)
	return shell.RecoverGeneratedShellIn(t.Context(), doc.Units(), document.MaxRegions, document.MaxScanBytes)
}
