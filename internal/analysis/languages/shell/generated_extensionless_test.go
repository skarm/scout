package shell_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestGeneratedShellRecognizesShebangWithoutShellExtension(t *testing.T) {
	for _, tc := range []struct {
		name, input, body string
	}{
		{"absolute shell", "cat >setup <<'END'\n#!/bin/sh\nprintf example\nEND\n", "#!/bin/sh\nprintf example\n"},
		{"env split options", "tee -- setup note >/dev/null <<'END'\n#!/usr/bin/env -S bash -eu\nprintf example\nEND\n", "#!/usr/bin/env -S bash -eu\nprintf example\n"},
		{"other extension", "cat >setup.txt <<'END'\n#!/usr/bin/env sh\nprintf example\nEND\n", "#!/usr/bin/env sh\nprintf example\n"},
		{"tab stripping", "cat >setup <<-'END'\n\t#!/bin/bash\n\tprintf example\n\tEND\n", "#!/bin/bash\nprintf example\n"},
		{"unquoted line continuation", "cat >setup <<END\n#!/bin/ba\\\nsh\nprintf example\nEND\n", "#!/bin/bash\nprintf example\n"},
		{"known interpreter parameter", "runner=/bin/sh\ncat >setup <<END\n#!$runner\nprintf example\nEND\n", "#!/bin/sh\nprintf example\n"},
		{"known empty base and appended shebang", "cat >setup <<'EMPTY'\nEMPTY\ncat >>setup <<'END'\n#!/bin/sh\nprintf example\nEND\n", "#!/bin/sh\nprintf example\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.input)
			if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != tc.body {
				t.Fatalf("unexpected shebang recovery: %+v", got)
			}
			view := got.Views[0]
			at := strings.Index(view.Text(), "printf example")
			span, err := view.Original(source.Span{Start: at, End: at + len("printf example")})
			if err != nil || tc.input[span.Start:span.End] != "printf example" {
				t.Fatalf("body mapped to %+v: %v", span, err)
			}
		})
	}
}

func TestGeneratedShellRecognizesExtensionlessExecution(t *testing.T) {
	const write = "cat >setup <<'END'\nprintf example\nEND\n"
	for _, tc := range []struct{ name, suffix, invocation string }{
		{"bash", "bash setup\n", "bash setup"},
		{"sh", "/bin/sh -- ./setup\n", "/bin/sh -- ./setup"},
		{"source", "source ./setup\n", "source ./setup"},
		{"dot", ". ./setup\n", ". ./setup"},
		{"direct", "chmod +x setup\n./setup\n", "./setup"},
		{"direct with absolute chmod", "/bin/chmod +x setup\n./setup\n", "./setup"},
		{"exec", "exec -- ./setup\n", "exec -- ./setup"},
		{"direct from known variable", "run=./setup\n\"$run\"\n", `"$run"`},
		{"source inside a function", "load() {\n. ./setup\n}\nload\n", ". ./setup"},
		{"after changing directory", "cd sub\nsh ../setup\n", "sh ../setup"},
		{"unrelated data write", "cat >data <<'END'\nnotes\nEND\nbash ./setup\n", "bash ./setup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := write + tc.suffix
			got := recoverGeneratedShell(t, text)
			if got.Gaps != 0 || len(got.Views) != 1 || len(got.Executions) != 1 || got.ExecutionLimited {
				t.Fatalf("unexpected extensionless recovery: %+v", got)
			}
			link := got.Executions[0]
			if text[link.Use.Start:link.Use.End] != tc.invocation || text[link.Body.Start:link.Body.End] != "printf example\n" ||
				text[link.Write.Start:link.Write.End] != "cat >setup <<'END'" {
				t.Fatalf("incorrect write/body/use source coordinates: %+v", link)
			}
		})
	}
}

func TestGeneratedShellExplicitInterpreterOverridesShebang(t *testing.T) {
	const text = "cat >setup <<'END'\n#!/usr/bin/python3\nprintf example\nEND\nbash ./setup\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || len(got.Executions) != 1 || got.Views[0].Text() != "#!/usr/bin/python3\nprintf example\n" {
		t.Fatalf("explicit shell invocation did not recover the body: %+v", got)
	}
	link := got.Executions[0]
	if text[link.Use.Start:link.Use.End] != "bash ./setup" {
		t.Fatalf("unexpected invocation location: %+v", link.Use)
	}
}

func TestGeneratedShellLeavesUnconfirmedFilesOutOfAnalysis(t *testing.T) {
	const write = "cat >setup <<'END'\nprintf example\nEND\n"
	for _, tc := range []struct{ name, text string }{
		{"ordinary data", write},
		{"source path lookup", write + "source setup\n"},
		{"executable path lookup", write + "setup\n"},
		{"syntax only", write + "bash -n ./setup\n"},
		{"command string", write + "bash -c ./setup\n"},
		{"different destination", write + "sh ./other\n"},
		{"interpreter operand requires a directory", write + "sh ./setup/\n"},
		{"direct path requires a directory", write + "./setup/.\n"},
		{"source operand requires a directory", write + "source ./setup/\n"},
		{"intervening overwrite", write + "printf changed >setup\nsh ./setup\n"},
		{"unknown mutation", write + "custom-command\nsh ./setup\n"},
		{"shadowed interpreter", "bash() { :; }\n" + write + "bash ./setup\n"},
		{"python shebang with shell-looking argument", "cat >setup <<'END'\n#!/usr/bin/python3 sh\nprint('example')\nEND\n./setup\n"},
		{"unknown interpreter with shell-looking argument", "cat >setup <<'END'\n#!/usr/bin/other sh\nprintf example\nEND\n./setup\n"},
		{"foreign env interpreter", "cat >setup <<'END'\n#!/usr/bin/env -S python3 sh\nprint('example')\nEND\n./setup\n"},
		{"env terminator prevents further options", "cat >setup <<'END'\n#!/usr/bin/env -S -- -i bash\nprintf example\nEND\n"},
		{"env assignment is not an interpreter", "cat >setup <<'END'\n#!/usr/bin/env PATH=/custom/bash\nprintf example\nEND\n"},
		{"leading whitespace before shebang", "cat >setup <<'END'\n #!/bin/sh\nprintf example\nEND\n"},
		{"unknown expansion in unused data", "cat >setup <<END\n$value\nEND\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != 0 || len(got.Views) != 0 || len(got.Executions) != 0 || got.ExecutionLimited {
				t.Fatalf("unconfirmed file became shell evidence: %+v", got)
			}
		})
	}
}

func TestGeneratedShellRecoversLatestExtensionlessVersion(t *testing.T) {
	const initial = "cat >setup <<'END'\nprintf old\nEND\n"
	const latest = "verb=printf\ncat >setup <<END\n$verb new\nEND\nverb=echo\nsh ./setup\n"
	got := recoverGeneratedShell(t, initial+latest)
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf new\n" || len(got.Executions) != 1 {
		t.Fatalf("unexpected version or bindings: %+v", got)
	}
	span, err := got.Views[0].Original(source.Span{End: len("printf")})
	if err != nil || (initial + latest)[span.Start:span.End] != "$verb" {
		t.Fatalf("deferred expansion mapped to %+v: %v", span, err)
	}
}

func TestGeneratedShellMatchesSameQuotedVariableAtWriteAndUse(t *testing.T) {
	const start = "script=./setup\ncat >\"$script\" <<'END'"
	const body = "\nprintf example\nEND\n"
	for _, text := range []string{start + body + "bash \"$script\"\n", start + " && bash \"$script\"" + body} {
		got := recoverGeneratedShell(t, text)
		if got.Gaps != 0 || len(got.Views) != 1 || len(got.Executions) != 1 || got.Views[0].Text() != "printf example\n" {
			t.Fatalf("lost a known path across the write: %+v", got)
		}
	}
}

func TestGeneratedShellExtensionlessAppendRetainsAllSourceFragments(t *testing.T) {
	const base = "cat >setup <<'END'\nprintf first\nEND\n"
	const app = "tee -a setup <<'END'\nprintf second\nEND\n"
	text := base + app + "bash ./setup\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf first\nprintf second\n" || len(got.Executions) != 1 {
		t.Fatalf("unexpected deferred append: %+v", got)
	}
	span := got.Executions[0].Transforms[0]
	if text[span.Start:span.End] != "printf second\n" {
		t.Fatalf("unexpected append evidence: %+v", span)
	}
}

func TestGeneratedShellExtensionlessUnresolvedAppendPointsToAppend(t *testing.T) {
	const base = "cat >setup <<'END'\nprintf first\nEND\n"
	const text = base + "cat >>setup <<END\n$value\nEND\nsh setup\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != document.GeneratedShellAppend || len(got.Views) != 0 || len(got.Executions) != 0 || len(got.Issues) != 1 {
		t.Fatalf("unexpected recovery with unresolved append: %+v", got)
	}
	if issue := got.Issues[0]; issue.At != len(base) || issue.Reason != document.GeneratedShellExpansion {
		t.Fatalf("incorrect append diagnostic: %+v", issue)
	}
}

func TestGeneratedShellExtensionlessCoverageGapsRequireShellEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		gap        document.GeneratedShellGaps
	}{
		{"executed unknown expansion", "cat >setup <<END\n$value\nEND\nbash setup\n", document.GeneratedShellUnrecovered},
		{"shebang followed by unknown expansion", "cat >setup <<END\n#!/bin/sh\n$value\nEND\n", document.GeneratedShellUnrecovered},
		{"shebang and unknown destination", "cat >\"$out\" <<'END'\n#!/bin/sh\nprintf example\nEND\n", document.GeneratedShellDynamicPath},
		{"executed append with unknown base", "cat >>setup <<'END'\nprintf example\nEND\nsh setup\n", document.GeneratedShellAppend},
		{"unused append with unknown base", "cat >>setup <<'END'\nprintf example\nEND\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if got.Gaps != tc.gap || len(got.Views) != 0 || len(got.Executions) != 0 {
				t.Fatalf("unexpected coverage: %+v", got)
			}
			if tc.gap != 0 && (len(got.Issues) != 1 || got.Issues[0].At != 0) {
				t.Fatalf("gap lacks original write position: %+v", got.Issues)
			}
		})
	}
}

func TestGeneratedShellUnusedCandidatesDoNotSpendRecoveryQuota(t *testing.T) {
	const data = "cat >data <<END\n$value\nEND\n"
	const foreign = "cat >tool <<'END'\n#!/usr/bin/python3\nprint('example')\nEND\n./tool\n"
	const script = "cat >setup <<'END'\n#!/bin/sh\nprintf example\nEND\n"
	doc := generatedShellDocument(t, data+foreign+script)
	ctx := analysisbudget.WithLimit(t.Context(), 1)
	views, limited := shell.GeneratedScripts(ctx, doc)
	if limited || len(views) != 1 || !strings.HasPrefix(views[0].Text(), "#!/bin/sh\n") || analysisbudget.Used(ctx) != 1 {
		t.Fatalf("unused candidates consumed recovery quota: %d views, limited=%t", len(views), limited)
	}
}
