//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package releasecheck_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/skarm/scout/internal/dev/releasecheck"
)

func TestReleaseFIFORejectedBeforeOpenWaits(t *testing.T) {
	for _, operation := range []string{"inspect", "verify"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "release.fifo")
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "inspect" {
					_, err := releasecheck.Inspect(path)
					done <- err
					return
				}
				_, err := releasecheck.Verify(ctx, path)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO accepted as a release binary")
				}
			case <-time.After(500 * time.Millisecond):
				// Release the old blocking Open so a failing regression does not
				// leave a reader goroutine behind or require a captured payload.
				writer, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("release reader did not stop after FIFO release")
				}
				t.Fatal("release input waited for a FIFO writer before type checking")
			}
		})
	}
}
