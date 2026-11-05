//go:build linux || darwin || freebsd

//nolint:testpackage // Exercises the public reader and shared private admission boundary.
package provenance

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestEvidenceFIFORejectedBeforeOpenWaits(t *testing.T) {
	for _, alias := range []bool{false, true} {
		root := t.TempDir()
		fifo := filepath.Join(root, "evidence.fifo")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		name := "evidence.fifo"
		if alias {
			name = "alias.json"
			if err := os.Symlink("evidence.fifo", filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() {
			_, err := Read(root, name)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("FIFO accepted as evidence")
			}
		case <-time.After(time.Second):
			writer, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("evidence reader did not stop after FIFO release")
			}
			t.Fatal("evidence reader waited for a FIFO writer before rejecting nonregular input")
		}
	}
}
