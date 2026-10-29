package ingest_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/report"
)

func TestSelectedFilesCaptureExactBytesAndEnforceBounds(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, data string }{{name: "source.txt", data: "captured bytes"}, {
		name: "ARCHIVE.ZIP",
		data: "unparsed exact archive bytes",
	}} {
		name := filepath.Join(dir, tc.name)
		if err := os.WriteFile(name, []byte(tc.data), 0o700); err != nil {
			t.Fatal(err)
		}
		snapshot, err := ingest.Read(context.Background(), name, report.DefaultCaptureLimits())
		if err != nil || len(snapshot.Files()) != 1 || snapshot.Files()[0].Content() != tc.data || !snapshot.Files()[0].Metadata().Executable {
			t.Fatal(snapshot, err)
		}
	}
	limits := report.DefaultCaptureLimits()
	limits.MaxFileBytes = 4
	snapshot, err := ingest.Read(context.Background(), filepath.Join(dir, "source.txt"), limits)
	if err != nil || len(snapshot.Files()) != 0 || snapshot.Metadata().InventoryComplete {
		t.Fatal(snapshot, err)
	}
	for _, target := range []string{"", "https://example.invalid/x", filepath.Join(dir, "missing")} {
		if _, err := ingest.Read(context.Background(), target, report.DefaultCaptureLimits()); err == nil {
			t.Fatal(target)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "CON.txt"), []byte("unsafe name"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.Read(context.Background(), filepath.Join(dir, "CON.txt"), report.DefaultCaptureLimits()); err == nil || !strings.Contains(err.Error(), "filename") {
		t.Fatal(err)
	}
}
