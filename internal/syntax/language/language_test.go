package language_test

import (
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
