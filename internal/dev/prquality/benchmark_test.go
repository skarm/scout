package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkReviewDiff(b *testing.B) {
	for _, count := range []int{8, 128} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			dir := b.TempDir()
			b.Chdir(dir)
			gitTest(b, "init", "--quiet")
			gitTest(b, "config", "user.email", "benchmark@example.invalid")
			gitTest(b, "config", "user.name", "Scout Benchmark")
			gitTest(b, "config", "commit.gpgsign", "false")
			gitTest(b, "config", "core.hooksPath", filepath.Join(dir, "no-hooks"))
			writeCases := func(skip bool) {
				for n := range count {
					body := "t.Log(\"run fixture\")"
					if skip {
						body = "t.Log(\"reviewed fixture\")"
						if n%4 == 0 {
							body = "t.Skip(\"fixture disabled\")"
						}
					}
					filename := fmt.Sprintf("pkg%d/scanner_test.go", n)
					writeFile(b, filename, fmt.Sprintf("package scanner\nimport \"testing\"\nfunc TestScan(t *testing.T) { %s }\n", body))
				}
			}
			writeCases(false)
			save(b)
			base := gitTest(b, "rev-parse", "HEAD")
			writeCases(true)
			writeFile(b, ".github/workflows/ci.yml", "on: pull_request\njobs:\n  scan:\n    steps:\n      - run: go test ./...\n")
			save(b)
			head := gitTest(b, "rev-parse", "HEAD")

			b.ReportAllocs()
			for b.Loop() {
				warnings, err := reviewDiff(b.Context(), base, head)
				if err != nil || len(warnings) != count/4 {
					b.Fatalf("expected %d warnings, got %d: %v", count/4, len(warnings), err)
				}
			}
		})
	}
}
