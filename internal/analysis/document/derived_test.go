package document_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func TestGeneratedShellUsesOriginalParserBudget(t *testing.T) {
	const body = "echo one\necho two\n"
	const text = "# header\n" + body
	span := source.Span{Start: strings.Index(text, body), End: len(text)}
	view, err := source.NewView(text, []source.Span{span})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, status string
		parserBytes  int
		wantCalls    int
	}{
		{"exact budget", report.UnitParsedLimited, len(text) + len(body), 2},
		{"exhausted budget", "budget_exceeded", len(text) + len(body) - 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			registry, err := parse.New(candidateBackend{calls: &calls, bytes: tc.parserBytes})
			if err != nil {
				t.Fatal(err)
			}
			original := document.PrepareAllWithRegistry(t.Context(), []artifact.File{artifact.NewFile("setup.sh", []byte(text), false)}, registry)[0]
			prepared := original.WithGeneratedShell(t.Context(), []source.View{view}, false)
			units := prepared.Units()
			if calls != tc.wantCalls || len(units) != 2 || len(original.Units()) != 1 {
				t.Fatalf("parser calls=%d, units=%d, original units=%d", calls, len(units), len(original.Units()))
			}
			u := units[1]
			if u.Status != tc.status || u.Origin != "heredoc" || u.ParserID != "candidate-fixture" || u.Span != span || u.View.Text() != body {
				t.Fatalf("generated unit lost its parser or source mapping: %+v", u)
			}
			if got := has(prepared, "shell_scan_budget"); got != (tc.wantCalls == 1) {
				t.Fatalf("unexpected parser quota diagnostic: %+v", prepared.Diagnostics())
			}
		})
	}
}

func TestGeneratedShellRejectsInvalidAndFrozenPreparation(t *testing.T) {
	const text = "echo ok\n"
	view, err := source.NewView(text, []source.Span{{End: len(text)}})
	if err != nil {
		t.Fatal(err)
	}
	original := document.Prepare(t.Context(), artifact.NewFile("setup.sh", []byte(text), false))
	for _, tc := range []struct {
		name string
		doc  document.File
		view []source.View
		want int
	}{
		{"invalid mapping retains valid sibling", original, []source.View{{}, view}, 2},
		{"frozen registry cannot parse", document.Freeze([]document.File{original})[0], []source.View{view}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.doc.WithGeneratedShell(t.Context(), tc.view, false)
			if len(got.Units()) != tc.want || has(tc.doc, "generated_shell_incomplete") {
				t.Fatalf("unexpected units or mutation of original: units=%d, original diagnostics=%+v", len(got.Units()), tc.doc.Diagnostics())
			}
			for _, d := range got.Diagnostics() {
				if d.Code == "generated_shell_incomplete" && d.Path == "setup.sh" && d.AffectsScope {
					return
				}
			}
			t.Fatalf("missing source-scoped gap: %+v", got.Diagnostics())
		})
	}
}
