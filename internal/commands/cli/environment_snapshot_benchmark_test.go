package cli_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
)

func BenchmarkPolicyShadowSavedReport(b *testing.B) {
	base := b.TempDir()
	root := filepath.Join(base, "skill")
	if err := os.Mkdir(root, 0o700); err != nil {
		b.Fatal(err)
	}
	for index := range 64 {
		name := filepath.Join(root, fmt.Sprintf("note-%03d.md", index))
		if err := os.WriteFile(name, []byte("# Local notes\nSummarize nearby text.\n"), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	var raw bytes.Buffer
	if code := cli.Run(b.Context(), []string{"scan", "--profile", "custom", "--checks", "none", "--format", "json", root}, &raw, io.Discard); code != 0 {
		b.Fatal("create source report", code)
	}
	saved, current, trial := filepath.Join(base, "report.json"), filepath.Join(base, "current.json"), filepath.Join(base, "trial.json")
	for name, data := range map[string][]byte{
		saved: raw.Bytes(), current: []byte(`{"schema":"scout.config/v1"}`),
		trial: []byte(`{"schema":"scout.config/v1","policy":{"fail_at":"critical"}}`),
	} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	args := []string{"policy", "shadow", "--report", saved, "--current", current, "--trial", trial, "--format", "json"}
	b.ReportAllocs()
	for b.Loop() {
		if code := cli.Run(b.Context(), args, io.Discard, io.Discard); code != 0 {
			b.Fatal("compare sealed policies", code)
		}
	}
}

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
