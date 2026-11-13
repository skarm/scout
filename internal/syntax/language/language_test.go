package language_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/language"
)

func TestCandidates(t *testing.T) {
	for _, tc := range []struct{ name, data, want, basis string }{
		{name: "a.py", data: "", want: "python", basis: "extension"},
		{name: "a.ts", data: "", want: "typescript", basis: "extension"},
		{name: "a.js", data: "", want: "javascript", basis: "extension"},
		{name: "a.psm1", data: "", want: "powershell", basis: "extension"},
		{name: "a.rb", data: "", want: "ruby", basis: "extension"},
		{name: "a.pl", data: "", want: "perl", basis: "extension"},
		{name: "a.c", data: "", want: "c", basis: "extension"},
		{name: "a.cpp", data: "", want: "cpp", basis: "extension"},
		{name: "a.rs", data: "", want: "rust", basis: "extension"},
		{name: "a.cs", data: "", want: "csharp", basis: "extension"},
		{name: "a.java", data: "", want: "java", basis: "extension"},
		{name: "a.kt", data: "", want: "kotlin", basis: "extension"},
		{name: "a.swift", data: "", want: "swift", basis: "extension"},
		{name: "a.lua", data: "", want: "lua", basis: "extension"},
		{name: "a.bat", data: "", want: "batch", basis: "extension"},
		{name: "a.php", data: "", want: "php", basis: "extension"},
		{name: "a.go", data: "", want: "go", basis: "extension"},
		{name: "plugin.json", data: "", want: "json", basis: "extension"},
		{name: "image.svg", data: "", want: "xml", basis: "extension"},
		{name: "Dockerfile", data: "", want: "dockerfile", basis: "basename"},
		{name: ".bashrc", data: "", want: "shell", basis: "basename"},
		{name: "go.mod", data: "", want: "gomod", basis: "basename"},
		{name: "launch", data: "#!/usr/bin/env -S python3.12 -I\npass\n", want: "python", basis: "shebang"},
		{name: "data.txt", data: "#!/bin/sh\ntrue", want: "shell", basis: "shebang"},
		{name: "README.txt", data: "package p\nimport \"os\"", want: "go", basis: "content-prefix"},
		{name: "image.dat", data: "<?php echo 1;", want: "php", basis: "content-prefix"},
	} {
		t.Run(tc.name+"/"+tc.want, func(t *testing.T) {
			for _, h := range language.Detect(tc.name, tc.data) {
				if h.Language == tc.want && h.Basis == tc.basis {
					return
				}
			}
			t.Fatalf("missing %s/%s: %+v", tc.want, tc.basis, language.Detect(tc.name, tc.data))
		})
	}
}

func TestShebangSelectsInterpreterInsteadOfArguments(t *testing.T) {
	for _, tc := range []struct{ name, line, want string }{
		{"plain shell", "#!/bin/bash -eu", language.Shell},
		{"env shell", "#!/usr/bin/env sh", language.Shell},
		{"env split with options", "#!/usr/bin/env -S -i MODE=test /bin/sh -e", language.Shell},
		{"env split long option", "#!/usr/bin/env --split-string -- dash -e", language.Shell},
		{"python wins over shell argument", "#!/usr/bin/env -S python3.12 bash", language.Python},
		{"known TypeScript interpreter", "#!/usr/bin/env tsx", language.TypeScript},
		{"uv run", "#!/usr/bin/env -S uv run --script", language.Python},
		{"unknown interpreter", "#!/usr/bin/custom sh", language.Unknown},
		{"unknown env interpreter", "#!/usr/bin/env -S custom sh", language.Unknown},
		{"env needs split for multiple words", "#!/usr/bin/env sh -e", language.Unknown},
		{"env terminator prevents more options", "#!/usr/bin/env -S -- -i sh", language.Unknown},
		{"assignment is not executable", "#!/usr/bin/env PATH=/usr/bin/bash", language.Unknown},
		{"unresolved env variable", "#!/usr/bin/env -S ${BIN}/bash", language.Unknown},
		{"escaped space in an env assignment", "#!/usr/bin/env -S NAME=prefix\\ sh", language.Unknown},
		{"not an executable path", "#!/bin/sh/", language.Unknown},
		{"leading whitespace", " #!/bin/sh", language.Unknown},
		{"overlong incomplete header", "#!/usr/bin/env -S " + strings.Repeat(" ", 512) + "sh", language.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.line + "\ntrue\n"
			hints := language.Detect("tool", content)
			if tc.want == language.Unknown {
				if len(hints) != 0 {
					t.Fatalf("unsupported shebang yielded candidates: %+v", hints)
				}

				return
			}

			if len(hints) != 1 || hints[0].Language != tc.want {
				t.Fatalf("candidates = %+v, want only %s", hints, tc.want)
			}
		})
	}
}

func TestConflictsAndUnknownLabels(t *testing.T) {
	hints := language.Detect("x.py", "#!/bin/sh\ntrue")
	if len(hints) != 2 || hints[0].Language != "python" || hints[1].Language != "shell" {
		t.Fatalf("lost conflicting candidates: %+v", hints)
	}
	if language.Normalize("SECRET_SENTINEL") != "unknown" {
		t.Fatal("untrusted label echoed")
	}
	if language.Normalize("ts") == language.Normalize("js") {
		t.Fatal("TypeScript collapsed into JavaScript")
	}
	if language.Structured("markdown") || language.Structured("text") || language.Structured("unknown") {
		t.Fatal("nonlanguage presented as structured")
	}
}
