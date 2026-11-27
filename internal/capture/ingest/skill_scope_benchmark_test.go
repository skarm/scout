package ingest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/report"
)

func BenchmarkSkillScopedCapture(b *testing.B) {
	root := b.TempDir()
	for _, dir := range []string{"references", "tests/cases"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			b.Fatal(err)
		}
		for index := range 160 {
			name := filepath.Join(root, dir, fmt.Sprintf("case-%03d.md", index))
			if err := os.WriteFile(name, []byte("Ordinary captured content.\n"), 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("# Skill\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	scope, err := ingest.CompileSkillExclusions([]string{"cache/*", "fixtures/*.json", "tests/*"})
	if err != nil {
		b.Fatal(err)
	}
	limits := report.DefaultCaptureLimits()
	b.ReportAllocs()
	for b.Loop() {
		snapshot, err := ingest.ReadSkill(b.Context(), root, limits, scope)
		if err != nil || snapshot.Complete() {
			b.Fatalf("capture completeness changed: %v", err)
		}
	}
}
