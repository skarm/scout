//go:build unix

package ingest //nolint:testpackage // Exercises metadata changes between inspection and safe opening.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/report"
)

func TestSelectedFileRejectsChangedExecutableMetadata(t *testing.T) {
	for _, name := range []string{"payload", "payload.zip"} {
		for _, initialMode := range []os.FileMode{0o600, 0o700} {
			t.Run(name+"/"+initialMode.String(), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(path, []byte("inert capture bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, initialMode); err != nil {
					t.Fatal(err)
				}
				initial, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				stable, err := readFile(t.Context(), path, initial, report.DefaultCaptureLimits())
				if err != nil || len(stable.Files()) != 1 || !stable.Complete() || stable.Files()[0].Metadata().Executable != (initialMode&0o111 != 0) {
					t.Fatalf("stable capture = %+v, %v", stable, err)
				}
				if err := os.Chmod(path, initialMode^0o100); err != nil {
					t.Fatal(err)
				}
				changed, err := readFile(t.Context(), path, initial, report.DefaultCaptureLimits())
				if err == nil || len(changed.Files()) != 0 {
					t.Fatalf("changed executable metadata was published: %+v, %v", changed, err)
				}
			})
		}
	}
}
