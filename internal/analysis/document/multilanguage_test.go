package document_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestLanguageNeutralPreparation(t *testing.T) {
	for _, tc := range []struct{ label, want string }{{label: "python", want: "python"}, {label: "bash", want: "shell"}, {
		label: "ts",
		want:  "typescript",
	}, {
		label: "js",
		want:  "javascript",
	}, {
		label: "powershell",
		want:  "powershell",
	}, {
		label: "ruby",
		want:  "ruby",
	}, {
		label: "php",
		want:  "php",
	}, {
		label: "lua",
		want:  "lua",
	}, {
		label: "rust",
		want:  "rust",
	}, {
		label: "java",
		want:  "java",
	}, {
		label: "c++",
		want:  "cpp",
	}, {
		label: "text",
		want:  "text",
	}, {
		label: "SECRET_SENTINEL",
		want:  "unknown",
	}} {
		t.Run(tc.label, func(t *testing.T) {
			text := "  ```" + tc.label + "\r\n  command_here\r\n  ```\r\n"
			f := prepare(text)
			u := f.Units()
			wantStatus := "unsupported"
			if tc.want == "shell" {
				wantStatus = "parsed_limited"
			}
			if (tc.want == "javascript" || tc.want == "typescript") && scriptsyntax.Available() {
				wantStatus = "parsed_limited"
			}
			if len(u) != 1 || u[0].Language != tc.want || u[0].Status != wantStatus || u[0].Origin != "fenced-code" {
				t.Fatalf("got %+v", u)
			}
			if u[0].View.Text() != "command_here\r\n" {
				t.Fatalf("lost source: %q", u[0].View.Text())
			}
			span, err := u[0].View.Original(source.Span{Start: 0, End: len("command_here")})
			if err != nil || text[span.Start:span.End] != "command_here" {
				t.Fatal("non-Go source map lost")
			}
			u[0].Language = "changed"
			if f.Units()[0].Language != tc.want {
				t.Fatal("mutable units")
			}
		})
	}
}

func TestIndependentParserRegistration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend pythonStub
		status  string
	}{{name: "works", backend: pythonStub{}, status: "parsed_limited"}, {
		name:    "error",
		backend: pythonStub{fail: true},
		status:  "parse_error",
	}, {
		name:    "panic",
		backend: pythonStub{panicNow: true},
		status:  "failed",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parse.New(tc.backend)
			if err != nil {
				t.Fatal(err)
			}
			files := []artifact.File{artifact.NewFile("a.py", []byte("print('hello')"), false), artifact.NewFile("notes.txt", []byte("```python\nprint('hello')\n```"), false)}
			prepared := document.PrepareAllWithRegistry(context.Background(), files, r)
			for _, f := range prepared {
				u := f.Units()
				if len(u) != 1 || u[0].ParserID != "test-python" || u[0].Status != tc.status {
					t.Fatalf("parser not dispatched: %+v", u)
				}
				if len(f.Diagnostics()) == 0 {
					t.Fatal("test parser incorrectly certifies semantics")
				}
				for _, d := range f.Diagnostics() {
					if strings.Contains(d.Message, "SECRET_SENTINEL") {
						t.Fatal("parser exception leaked")
					}
				}
			}
		})
	}
}

func TestRenamedSourcesAndConflictingCandidates(t *testing.T) {
	f := document.Prepare(context.Background(), artifact.NewFile("instructions.txt", []byte("package p\nimport \"os/exec\"\nfunc f(){exec.Command(\"sh\")}"), false))
	if !f.HasGo() {
		t.Fatal("renamed Go candidate never parsed")
	}
	f = document.Prepare(context.Background(), artifact.NewFile("tool.py", []byte("#!/bin/sh\ntrue\n"), false))
	if len(f.Units()) != 2 || !f.Classification().Conflict {
		t.Fatalf("lost conflicting candidates: %+v", f.Units())
	}
	d := f.Classification()
	d.Languages[0].Language = "changed"
	if f.Classification().Languages[0].Language == "changed" {
		t.Fatal("mutable classification")
	}
}

type pythonStub struct{ fail, panicNow bool }

func (pythonStub) Descriptor() parse.Descriptor {
	return parse.Descriptor{ID: "test-python", Language: "python", Version: "1", UnitBytes: 1024, ScanBytes: 4096}
}

func (p pythonStub) Parse(ctx context.Context, v source.View) (any, error) {
	if p.panicNow {
		panic("SECRET_SENTINEL")
	}
	if p.fail {
		return "partial-test-tree", errors.New("SECRET_SENTINEL")
	}
	return v.Text(), ctx.Err()
}
