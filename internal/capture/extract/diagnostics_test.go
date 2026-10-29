package extract //nolint:testpackage // Exercises private extraction builders and encoding admission.

import (
	"strconv"
	"testing"

	"github.com/skarm/scout/internal/capture/artifact"
)

func TestDiagnosticsPreserveFirstEmissionAndPathCodeIdentity(t *testing.T) {
	b := builder{}
	for _, call := range []struct{ path, code, message string }{
		{path: "a", code: "first", message: "original"},
		{path: "a", code: "second", message: "next"},
		{path: "a", code: "first", message: "ignored"},
		{path: "b", code: "first", message: "other file"},
		{path: "a\x00b", code: "c", message: "embedded separator"},
		{path: "a", code: "b\x00c", message: "distinct key"},
	} {
		o := operation{b: &b, parent: queued{file: artifact.NewFile(call.path, nil, false)}}
		o.issue(call.code, call.message)
	}
	want := []string{"original", "next", "other file", "embedded separator", "distinct key"}
	if len(b.result.Diagnostics) != len(want) {
		t.Fatal(b.result.Diagnostics)
	}
	for i, d := range b.result.Diagnostics {
		if d.Message != want[i] || !d.AffectsScope {
			t.Fatal(b.result.Diagnostics)
		}
	}
}

func BenchmarkDiagnosticDeduplication(b *testing.B) {
	for _, size := range []int{128, 1024, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			files := make([]artifact.File, size)
			for i := range files {
				files[i] = artifact.NewFile(strconv.Itoa(i), nil, false)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				build := builder{}
				for _, f := range files {
					op := operation{b: &build, parent: queued{file: f}}
					op.issue("scope", "first")
					op.issue("scope", "duplicate")
				}
			}
		})
	}
}
