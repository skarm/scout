//nolint:testpackage // Exercises cancellation after Read's initial admission checks.
package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/scout/report"
)

func TestCancelledDirectoryCaptureIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "unread.txt"), []byte("not captured"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			}
			cancel()

			// Admission has already inspected the directory. Cancellation before
			// enumeration must not turn the unseen inventory into a complete one.
			snapshot, err := readDirectory(ctx, dir, initial, report.DefaultCaptureLimits())
			if !errors.Is(err, ctx.Err()) {
				t.Fatalf("capture error = %v, want %v", err, ctx.Err())
			}
			if snapshot.Complete() || snapshot.Metadata().InventoryComplete {
				t.Fatal("cancelled capture declared an unread directory complete")
			}
			if len(snapshot.Files()) != 0 {
				t.Fatal("cancelled capture inspected a file")
			}
		})
	}
}

func TestDirectoryCancellationRetainsCapturedFilesWithoutClaimingCompleteness(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	partial, completed := false, false
	for budget := int32(0); budget <= 64; budget++ {
		base, cancel := context.WithCancel(t.Context())
		ctx := &capturePollingContext{Context: base, cancel: cancel}
		ctx.remaining.Store(budget)
		snapshot, err := Read(ctx, dir, report.DefaultCaptureLimits())
		files := snapshot.Files()
		if base.Err() != nil {
			if !errors.Is(err, context.Canceled) || snapshot.Complete() || snapshot.Metadata().InventoryComplete {
				t.Fatalf("cancelled inventory: budget=%d complete=%t error=%v", budget, snapshot.Complete(), err)
			}
			partial = partial || len(files) > 0 && len(files) < 3
		} else {
			completed = true
			if err != nil || !snapshot.Complete() || len(files) != 3 {
				t.Fatalf("uncancelled inventory: budget=%d files=%d complete=%t error=%v", budget, len(files), snapshot.Complete(), err)
			}
		}
		for _, file := range files {
			if file.Content() != file.Metadata().Path {
				t.Fatalf("captured file changed: %+v", file.Metadata())
			}
		}
		cancel()
	}
	if !partial || !completed {
		t.Fatal("cancellation schedules must exercise partial and completed captures")
	}
}

// Trigger real cancellation at different cooperative boundaries. Assertions use
// the underlying context, without assuming a particular order of polling calls.
type capturePollingContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining atomic.Int32
}

func (c *capturePollingContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.remaining.Add(-1) < 0 {
		c.cancel()
	}
	return c.Context.Err()
}
