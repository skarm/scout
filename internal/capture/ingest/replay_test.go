package ingest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/report"
)

func TestStableInputCaptureHonorsNewLimits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("Local text."), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := ingest.WithStableInputs(t.Context(), map[string]string{"notes": root})
	limits := report.DefaultCaptureLimits()
	first, err := ingest.Read(ctx, root, limits)
	if err != nil || !first.Complete() {
		t.Fatal("initial complete capture", err)
	}
	limits.MaxFileBytes = 1
	partial, err := ingest.Read(ctx, root, limits)
	if err != nil || partial.Complete() || len(partial.Files()) != 0 {
		t.Fatal("cached bytes bypassed the tighter budget", err)
	}
	limits = report.DefaultCaptureLimits()
	again, err := ingest.Read(ctx, root, limits)
	if err != nil || !reflect.DeepEqual(first.Metadata(), again.Metadata()) {
		t.Fatal("partial capture replaced complete evidence", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ingest.Read(cancelled, root, limits); !errors.Is(err, context.Canceled) {
		t.Fatal("cached capture bypassed cancellation", err)
	}
}
