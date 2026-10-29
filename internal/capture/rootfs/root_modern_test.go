//go:build !linux && !darwin && go1.24

package rootfs_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/capture/rootfs"
)

func TestModernRootAdmitsOnlyStableLocalEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("captured"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := rootfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file", "directory"} {
		f, err := r.Open(name)
		if err != nil {
			t.Fatal(name, err)
		}
		info, err := f.Stat()
		if err != nil || info.Name() != name {
			t.Fatal(name, info, err)
		}
		if info.IsDir() != (name == "directory") {
			t.Fatal("entry type changed", name, info.Mode())
		}
		if name == "file" {
			data, err := io.ReadAll(f)
			if err != nil || string(data) != "captured" {
				t.Fatal("file bytes changed", string(data), err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", "../file", "/file", `directory\file`, "missing"} {
		if f, err := r.Open(name); err == nil || f != nil {
			t.Fatal("invalid or absent entry admitted", name, f, err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "file"), filepath.Join(dir, "link")); err == nil {
		if f, err := r.Open("link"); err == nil || f != nil {
			t.Fatal("symlink admitted", f, err)
		}
	}
	locked := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(locked, []byte("private"), 0o000); err != nil {
		t.Fatal(err)
	}
	// Some hosts (Windows ACLs or a privileged test process) do not enforce
	// these mode bits. Only assert the denial when ordinary open proves it.
	if file, err := os.Open(locked); err == nil {
		file.Close()
	} else if !os.IsPermission(err) {
		t.Fatal(err)
	} else if file, err := r.Open("unreadable"); file != nil || !os.IsPermission(err) {
		t.Fatal("root changed the file permission refusal", file, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if f, err := r.Open("file"); err == nil || f != nil {
		t.Fatal("closed root admitted a file", f, err)
	}
	if root, err := rootfs.Open(filepath.Join(dir, "missing")); err == nil || root != nil {
		t.Fatal("missing root admitted", root, err)
	}
}
