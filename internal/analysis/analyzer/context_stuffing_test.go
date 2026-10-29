//nolint:testpackage // Exercises private implementation details and local test fixtures.
package analyzer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
)

func TestContextRepetitionFindGrammarAndByteSpans(t *testing.T) {
	tests := []struct {
		name, text string
		start, end int
	}{
		{name: "twenty repeats", text: strings.Repeat("AB", 20), start: 0, end: 0},
		{name: "twenty one repeats", text: strings.Repeat("AB", 21), start: 0, end: 42},
		{
			name:  "newline splits short runs",
			text:  strings.Repeat("AB", 20) + "\n" + strings.Repeat("AB", 20),
			start: 0,
			end:   0,
		},
		{name: "newline flushes accepted run", text: strings.Repeat("AB", 21) + "\nend", start: 0, end: 42},
		{
			name:  "Unicode source bytes",
			text:  "π " + strings.Repeat("Жβ", 21),
			start: len("π "),
			end:   len("π " + strings.Repeat("Жβ", 21)),
		},
		{name: "short punctuation layout", text: strings.Repeat("-=", 21), start: 0, end: 0},
		{name: "long punctuation displacement", text: strings.Repeat("-=", 129), start: 0, end: 258},
		{name: "maximum phrase width", text: strings.Repeat("abcdefghijklmnopqrst", 21), start: 0, end: 420},
		{name: "phrase beyond bounded width", text: strings.Repeat("abcdefghijklmnopqrstu", 21), start: 0, end: 0},
	}
	a := patternAnalyzerForTest(t, "NV-MP2")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := document.Prepare(context.Background(), artifact.NewFile("input.txt", []byte(tt.text), false))
			got, err := a.Find(context.Background(), doc, 100)
			wantCount := 0
			if tt.end > 0 {
				wantCount = 1
			}
			if err != nil || got.Truncated || len(got.Matches) != wantCount {
				t.Fatalf("repetition grammar: %+v, %v; want %d matches", got, err, wantCount)
			}
			if wantCount > 0 && (got.Matches[0].Start != tt.start || got.Matches[0].End != tt.end) {
				t.Fatalf("source byte span: %+v, want [%d,%d)", got, tt.start, tt.end)
			}
		})
	}
}

func TestContextRepetitionFindBudgetPreservesPeriodOrder(t *testing.T) {
	first := strings.Repeat("AB", 21)
	second := strings.Repeat("CD", 21)
	tests := []struct {
		name, text string
		start, end int
	}{
		{name: "terminal flush exhausts budget", text: first + "\n" + second, start: 0, end: len(first)},
		{name: "boundary flush exhausts budget", text: first + "\n" + second + "\nend", start: 0, end: len(first)},
		{name: "shorter period is admitted first", text: strings.Repeat("ABC", 21) + "\n" + second, start: 64, end: 106},
	}
	a := patternAnalyzerForTest(t, "NV-MP2")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := document.Prepare(context.Background(), artifact.NewFile("input.txt", []byte(tt.text), false))
			got, err := a.Find(context.Background(), doc, 1)
			if err != nil || !got.Truncated || len(got.Matches) != 1 || got.Matches[0].Start != tt.start || got.Matches[0].End != tt.end {
				t.Fatalf("budget lost period-major evidence: %+v, %v; want [%d,%d)", got, err, tt.start, tt.end)
			}
		})
	}
}

func TestContextRepetitionFindCancellationKeepsEarlierRun(t *testing.T) {
	text := strings.Repeat("AB", 21) + "\n" + strings.Repeat("x", 5000)
	doc := document.Prepare(context.Background(), artifact.NewFile("input.txt", []byte(text), false))
	// MP2's five literal grammars run before the bounded repetition scan. The
	// sixth context check cancels its first 4096-rune checkpoint after AB emits.
	ctx := &patternCancelContext{Context: context.Background(), until: 6}
	got, err := patternAnalyzerForTest(t, "NV-MP2").Find(ctx, doc, 10)
	if !errors.Is(err, context.Canceled) || !got.Truncated || len(got.Matches) != 1 || got.Matches[0].Start != 0 || got.Matches[0].End != 42 {
		t.Fatalf("cancellation discarded prior repetition: %+v, %v", got, err)
	}
}
