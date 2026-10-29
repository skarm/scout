package signatures_test

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/signatures"
)

func FuzzLongBase64Spans(f *testing.F) {
	for _, s := range []string{"", strings.Repeat("x", 119) + "==", strings.Repeat("x", 120) + "==", strings.Repeat("+/", 70) + "=\x00" + strings.Repeat("a", 122), strings.Repeat("x", 4100) + "=="} {
		f.Add([]byte(s))
	}
	original := regexp.MustCompile(`^[A-Za-z0-9+/]{120,}={0,2}`)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			data = data[:8192]
		}
		var want []signatures.Span
		for at := 0; at < len(data) && len(want) < 9; at++ {
			if match := original.FindIndex(data[at:min(len(data), at+4095)]); match != nil {
				want = append(want, signatures.Span{Start: at, End: at + match[1]})
			}
		}
		if got := signatures.LongBase64SpansForTest(data); !slices.Equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})
}

func BenchmarkLongBase64Spans(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{name: "8KiB", size: 8192}, {name: "1MiB", size: 1 << 20}, {name: "4MiB", size: 4 << 20}} {
		b.Run(tc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), tc.size)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = signatures.LongBase64SpansForTest(data)
			}
		})
	}
}
