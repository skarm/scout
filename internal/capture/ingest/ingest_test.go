package ingest_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/capture/archiveutil"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/extract"
	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/report"
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
		t.Run(tc.name, func(t *testing.T) {
			err := ingest.ValidatePath(tc.name, 1024, 32)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v: %v", tc.ok, err)
			}
		})
	}
	if ingest.ValidatePath("aaa", 2, 32) == nil || ingest.ValidatePath("a/b", 1024, 1) == nil {
		t.Fatal("budget ignored")
	}
}

func TestZIPValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members []member
		ok      bool
	}{
		{name: "normal", members: []member{{name: "SKILL.md", content: "safe"}}, ok: true},
		{name: "unicode", members: []member{{name: "данные.md", content: "данные"}}, ok: true},
		{name: "traversal", members: []member{{name: "../escape", content: "bad"}}, ok: false},
		{name: "backslash", members: []member{{name: `a\b`, content: "bad"}}, ok: false},
		{name: "absolute", members: []member{{name: "/a", content: "bad"}}, ok: false},
		{name: "duplicate", members: []member{{name: "a"}, {name: "a"}}, ok: false},
		{name: "case-collision", members: []member{{name: "A"}, {name: "a"}}, ok: false},
		{name: "unicode-fold", members: []member{{name: "K.txt"}, {name: "K.txt"}}, ok: false},
		{name: "prefix-conflict", members: []member{{name: "a"}, {name: "a/b"}}, ok: false},
		{name: "implicit-dir-case", members: []member{{name: "A/x"}, {name: "a/y"}}, ok: false},
		{
			name:    "link",
			members: []member{{name: "link", content: "/etc/passwd", mode: os.ModeSymlink | 0o777}},
			ok:      false,
		},
		{name: "device", members: []member{{name: "device", mode: os.ModeDevice | 0o600}}, ok: false},
		{
			name: "directory",
			members: []member{{name: "a/", mode: os.ModeDir | 0o755}, {
				name:    "a/SKILL.md",
				content: "ok",
			}},
			ok: true,
		},
		{name: "reserved", members: []member{{name: "CON"}}, ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := openZIP(context.Background(), makeZIP(t, tc.members...), report.DefaultCaptureLimits())
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v: %v", tc.ok, err)
			}
			if tc.ok && (s == nil || len(s.File) == 0) {
				t.Fatal("incomplete valid ZIP")
			}
		})
	}
}

func TestZIPLimitsAndCorruption(t *testing.T) {
	t.Run("file-budget", func(t *testing.T) {
		l := report.DefaultExtractionLimits()
		l.MaxObjectBytes = 4
		data := makeZIP(t, member{name: "a", content: "12345"})
		r, err := extract.Expand(context.Background(), []artifact.File{artifact.NewFile("x.zip", data, false)}, l)
		if err != nil || len(r.Files) != 0 || len(r.Report.Skipped) != 1 || r.Report.Skipped[0].Reason != "object_byte_limit" {
			t.Fatalf("bad result: %v %+v", err, r.Report)
		}
	})
	t.Run("inventory-budget", func(t *testing.T) {
		l := report.DefaultCaptureLimits()
		l.MaxEntries = 1
		l.MaxFiles = 1
		_, err := openZIP(context.Background(), makeZIP(t, member{name: "a"}, member{name: "b"}), l)
		if err == nil {
			t.Fatal("entry cap ignored")
		}
	})
	t.Run("local-name-mismatch", func(t *testing.T) {
		data := makeZIP(t, member{name: "a", content: "hello"})
		data[30] = 'b'
		if _, err := openZIP(context.Background(), data, report.DefaultCaptureLimits()); err == nil {
			t.Fatal("mismatched names accepted")
		}
	})
	t.Run("checksum", func(t *testing.T) {
		data := makeZIP(t, member{name: "a", content: "hello"})
		central := bytes.Index(data, []byte{'P', 'K', 1, 2})
		data[central+16] ^= 0xff
		if _, err := openZIP(context.Background(), data, report.DefaultCaptureLimits()); err == nil {
			t.Fatal("bad checksum accepted")
		}
	})
	t.Run("zip64", func(t *testing.T) {
		data := makeZIP(t, member{name: "a"})
		binary.LittleEndian.PutUint16(data[len(data)-12:len(data)-10], 0xffff)
		if _, err := openZIP(context.Background(), data, report.DefaultCaptureLimits()); err == nil {
			t.Fatal("zip64 marker accepted")
		}
	})
	t.Run("empty", func(t *testing.T) {
		reader, err := openZIP(context.Background(), makeZIP(t), report.DefaultCaptureLimits())
		if err != nil || len(reader.File) != 0 {
			t.Fatalf("empty ZIP envelope: %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := openZIP(ctx, makeZIP(t, member{name: "a"}), report.DefaultCaptureLimits())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%v", err)
		}
	})
	for n := range 22 {
		if _, err := openZIP(context.Background(), make([]byte, n), report.DefaultCaptureLimits()); err == nil {
			t.Fatal("short header accepted")
		}
	}
}

func TestDirectoryLinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("HOST_SECRET_SENTINEL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("benign"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ingest.Read(context.Background(), root, report.DefaultCaptureLimits())
	if err != nil {
		t.Fatal(err)
	}
	if s.Complete() {
		t.Fatal("link omission marked complete")
	}
	for _, f := range s.Files() {
		if strings.Contains(f.Content(), "HOST_SECRET") {
			t.Fatal("host content escaped")
		}
	}
	if _, err := ingest.Read(context.Background(), filepath.Join(root, "link.md"), report.DefaultCaptureLimits()); err == nil {
		t.Fatal("selected link allowed")
	}
}

func TestDirectoryLimits(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.md", "b.md", "c.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*report.CaptureLimits)
	}{
		{name: "entries", change: func(l *report.CaptureLimits) { l.MaxEntries = 2; l.MaxFiles = 2 }},
		{name: "files", change: func(l *report.CaptureLimits) { l.MaxFiles = 1 }},
		{name: "bytes", change: func(l *report.CaptureLimits) { l.MaxFileBytes = 5; l.MaxTotalBytes = 5 }},
		{name: "file-size", change: func(l *report.CaptureLimits) { l.MaxFileBytes = 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := report.DefaultCaptureLimits()
			tc.change(&l)
			s, err := ingest.Read(context.Background(), root, l)
			if err != nil {
				t.Fatal(err)
			}
			if s.Complete() {
				t.Fatal("budget silently ignored")
			}
		})
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
		_ = ingest.ValidatePath(s, 1024, 32)
	})
}

func FuzzZIPNoPanic(f *testing.F) {
	f.Add([]byte("PK"))
	f.Add(makeZIP(f, member{name: "SKILL.md", content: "hello"}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			t.Skip()
		}
		l := report.DefaultCaptureLimits()
		l.MaxArchiveBytes = 4096
		l.MaxEntries = 16
		l.MaxFiles = 16
		l.MaxFileBytes = 1024
		l.MaxTotalBytes = 4096
		_, _ = openZIP(context.Background(), b, l)
	})
}

type member struct {
	name, content string
	mode          os.FileMode
}

func makeZIP(t testing.TB, members ...member) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.mode != 0 {
			h.SetMode(m.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(m.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func openZIP(ctx context.Context, data []byte, limits report.CaptureLimits) (*zip.Reader, error) {
	return archiveutil.OpenZIP(ctx, data, limits.MaxEntries, limits.MaxPathBytes, limits.MaxDepth)
}
