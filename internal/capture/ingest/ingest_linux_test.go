//go:build linux

package ingest_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/report"
)

func TestFIFORefused(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("safe"), 0o600)
	s, err := ingest.Read(context.Background(), root, report.DefaultCaptureLimits())
	if err != nil || s.Complete() {
		t.Fatalf("fifo: complete=%v err=%v", s.Complete(), err)
	}
}

func TestDescriptorAnchoredRoot(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "root")
	os.Mkdir(original, 0o700)
	os.WriteFile(filepath.Join(original, "a"), []byte("original"), 0o600)
	r, err := rootfs.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Rename(original, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	os.WriteFile(filepath.Join(external, "a"), []byte("host"), 0o600)
	if err := os.Symlink(external, original); err != nil {
		t.Fatal(err)
	}
	file, err := r.Open("a")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	b := make([]byte, 8)
	n, err := file.Read(b)
	if err != nil || string(b[:n]) != "original" {
		t.Fatalf("root changed: %q %v", b[:n], err)
	}
	for _, name := range []string{"../a", "/a", `a\b`} {
		if f, err := r.Open(name); err == nil {
			f.Close()
			t.Fatalf("escaped root: %s", name)
		}
	}
}
