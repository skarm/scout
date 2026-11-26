package cli_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
)

func BenchmarkEnvironmentCheckpointCompare(b *testing.B) {
	base := b.TempDir()
	saved := filepath.Join(base, "saved.json")
	roots := make([]string, 0, 4)
	for _, id := range []string{"notes", "rules"} {
		root := filepath.Join(base, id)
		if err := os.Mkdir(root, 0o700); err != nil {
			b.Fatal(err)
		}
		for i := range 8 {
			name := filepath.Join(root, fmt.Sprintf("note-%02d.md", i))
			content := "# Notes\n\n" + strings.Repeat("Preserve headings and ordinary text.\n", 180)
			if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
				b.Fatal(err)
			}
		}
		roots = append(roots, "--root", id+"="+root)
	}
	if code := cli.Run(b.Context(), checkpointArgs("create", saved, roots...), io.Discard, io.Discard); code != 0 {
		b.Fatal("create checkpoint", code)
	}
	args := checkpointArgs("compare", saved, "--format", "text")
	b.ReportAllocs()
	for b.Loop() {
		if code := cli.Run(b.Context(), args, io.Discard, io.Discard); code != 0 {
			b.Fatal("compare checkpoint", code)
		}
	}
}
