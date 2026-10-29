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

func TestPaddingMarkdownTableGrammar(t *testing.T) {
	spaces := strings.Repeat(" ", 80)
	header := "| é" + spaces + "| z |"
	delimiter := "|:" + strings.Repeat("-", 80) + ":|---|"
	row := "| λ" + spaces + "| x |"
	tests := []struct {
		name, path, text string
		want             []string
	}{
		{name: "aligned Unicode columns", path: "input.Md", text: header + "\n" + delimiter + "\n" + row, want: nil},
		{
			name: "indented table",
			path: "input.markdown",
			text: "  " + header + "\n  " + delimiter + "\n  " + row + "\n",
			want: nil,
		},
		{
			name: "plain text has no table exemption",
			path: "input.txt",
			text: header + "\n" + delimiter + "\n" + row,
			want: []string{spaces, spaces},
		},
		{
			name: "shifted row",
			path: "input.md",
			text: header + "\n" + delimiter + "\n| xx" + spaces + "| x |",
			want: []string{spaces},
		},
		{
			name: "extra cell ends table",
			path: "input.md",
			text: header + "\n" + delimiter + "\n| λ" + spaces + "| extra | x |",
			want: []string{spaces},
		},
		{
			name: "ordinary line ends table",
			path: "input.md",
			text: header + "\n" + delimiter + "\nprefix" + spaces + "suffix",
			want: []string{spaces},
		},
		{
			name: "missing closing pipe",
			path: "input.md",
			text: header + "\n" + delimiter + "\n| λ" + spaces + "x",
			want: []string{spaces},
		},
		{
			name: "tabs are not alignment spaces",
			path: "input.md",
			text: header + "\n" + delimiter + "\n| λ\t" + spaces[:79] + "| x |",
			want: []string{"\t" + spaces[:79]},
		},
		{
			name: "invalid delimiter cell",
			path: "input.md",
			text: header + "\n|" + strings.Repeat("-", 82) + "| x |\n" + row,
			want: []string{spaces, spaces},
		},
		{
			name: "delimiter has extra cell",
			path: "input.md",
			text: header + "\n" + delimiter + "---|\n" + row,
			want: []string{spaces, spaces},
		},
		{
			name: "header lacks opening pipe",
			path: "input.md",
			text: "x é" + spaces + "| z |\n" + delimiter + "\n" + row,
			want: []string{spaces, spaces},
		},
	}
	a := patternAnalyzerForTest(t, "NV-P9")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := document.Prepare(context.Background(), artifact.NewFile(tt.path, []byte(tt.text), false))
			got, err := a.Find(context.Background(), doc, 10)
			if err != nil || got.Truncated || len(got.Matches) != len(tt.want) {
				t.Fatalf("table grammar: %+v, %v; want %d matches", got, err, len(tt.want))
			}
			for i, match := range got.Matches {
				if observed := tt.text[match.Start:match.End]; observed != tt.want[i] {
					t.Fatalf("match %d byte span [%d,%d) = %q, want %q", i, match.Start, match.End, observed, tt.want[i])
				}
			}
		})
	}
}

func TestPaddingFindBudgetAndCancellationKeepEvidence(t *testing.T) {
	spaces := strings.Repeat(" ", 80)
	text := "a" + spaces + "b\nc" + spaces + "d"
	doc := document.Prepare(context.Background(), artifact.NewFile("input.md", []byte(text), false))
	a := patternAnalyzerForTest(t, "NV-P9")
	for _, budget := range []int{0, 1, 2} {
		got, err := a.Find(context.Background(), doc, budget)
		if err != nil || got.Truncated != (budget < 2) || len(got.Matches) != budget {
			t.Fatalf("budget %d: %+v, %v", budget, got, err)
		}
		if budget > 0 && (got.Matches[0].Start != 1 || got.Matches[0].End != 81) {
			t.Fatalf("budget changed first evidence: %+v", got)
		}
	}
	ctx := &patternCancelContext{Context: context.Background(), until: 4}
	got, err := a.Find(ctx, doc, 10)
	if !errors.Is(err, context.Canceled) || len(got.Matches) != 1 || got.Matches[0].Start != 1 || got.Matches[0].End != 81 {
		t.Fatalf("cancellation discarded accepted padding: %+v, %v", got, err)
	}
}
