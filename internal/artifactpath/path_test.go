package artifactpath_test

import (
	"testing"

	"github.com/skarm/scout/internal/artifactpath"
)

func TestPortablePaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{name: "SKILL.md", ok: true},
		{name: "скрипты/a.txt", ok: true},
		{name: ".git/config", ok: true},
		{name: "__pycache__/a.pyc", ok: true},
		{name: "", ok: false},
		{name: ".", ok: false},
		{name: "..", ok: false},
		{name: "../a", ok: false},
		{name: "/etc/passwd", ok: false},
		{name: "C:/x", ok: false},
		{name: `a\..\b`, ok: false},
		{name: "a//b", ok: false},
		{name: "a/./b", ok: false},
		{name: "a/../b", ok: false},
		{name: "NUL.txt", ok: false},
		{name: "con", ok: false},
		{name: "COM1.txt", ok: false},
		{name: "LPT¹", ok: false},
		{name: "a. ", ok: false},
		{name: " a", ok: false},
		{name: "a/b.", ok: false},
		{name: "x:y", ok: false},
		{name: "a\x00", ok: false},
		{name: "\xff", ok: false},
		{name: "a\u202e.md", ok: false},
	} {
		name := tc.name
		if name == "" {
			name = "empty_path"
		}
		t.Run(name, func(t *testing.T) {
			err := artifactpath.Validate(tc.name, 1024, 32)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v: %v", tc.ok, err)
			}
		})
	}
	if artifactpath.Validate("aaa", 2, 32) == nil || artifactpath.Validate("a/b", 1024, 1) == nil {
		t.Fatal("budget ignored")
	}
}

func TestNamespace(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		dir  bool
	}{
		{a: "a", b: "A", dir: false}, {a: "K", b: "k", dir: false}, {a: "a", b: "a/b", dir: false}, {
			a:   "a/b",
			b:   "a",
			dir: false,
		}, {
			a:   "a",
			b:   "a",
			dir: true,
		},
	} {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			n := artifactpath.Namespace{MaxNodes: 10}
			if e := n.Add(tc.a, tc.dir); e != nil {
				t.Fatal(e)
			}
			if n.Add(tc.b, tc.dir) == nil {
				t.Fatal("namespace conflict accepted")
			}
		})
	}
	n := artifactpath.Namespace{MaxNodes: 1}
	if n.Add("a/b", false) == nil {
		t.Fatal("implied directories unbounded")
	}
}

func FuzzValidatePath(f *testing.F) {
	for _, s := range []string{"SKILL.md", "../x", "NUL", "a\x00", "__pycache__/x.pyc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			t.Skip()
		}
		_ = artifactpath.Validate(s, 1024, 32)
	})
}
