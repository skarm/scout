package dependencies_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestGoDeclarationsShareThePackageInventoryBudget(t *testing.T) {
	var module strings.Builder
	module.WriteString("module example.com/root\nrequire (\n")
	for i := range 4096 {
		fmt.Fprintf(&module, "example.com/dep%d v1.0.0\n", i)
	}
	module.WriteString(")\n")
	for _, first := range []artifact.File{
		artifact.NewFile("first/go.mod", []byte(module.String()), false),
		artifact.NewFile("first/package.json", []byte(`{"dependencies":{"sample":"1.2.3"}}`), false),
	} {
		t.Run(first.Metadata().Path, func(t *testing.T) {
			files := make([]artifact.File, 1, 4)
			files[0] = first
			for i := range 3 {
				files = append(files, artifact.NewFile(fmt.Sprintf("module%d/go.mod", i), []byte(module.String()), false))
			}
			docs := document.PrepareAll(t.Context(), files)
			result := dependencies.Collect(t.Context(), docs)
			if len(result.Declarations) != 8192 {
				t.Fatalf("shared declaration budget exceeded: got %d, want 8192", len(result.Declarations))
			}
			if len(result.Manifests) != len(files) || !result.Manifests[0].InventoryComplete() {
				t.Fatalf("previous evidence or later manifest inventory lost: %+v", result.Manifests)
			}
			if result.Manifests[len(result.Manifests)-1].Status != report.OutcomePartial {
				t.Fatalf("omitted declarations reported as complete: %+v", result.Manifests)
			}
		})
	}
}

func TestSpecificReplacementPrecedence(t *testing.T) {
	text := `module example.com/root
require example.com/dependency v1.2.3
replace example.com/dependency => example.com/wildcard v1.0.0
replace example.com/dependency v1.2.3 => example.com/specific v1.2.4
`
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("go.mod", []byte(text), false)})
	r := dependencies.Collect(context.Background(), docs)
	if len(r.Declarations) != 1 || r.Declarations[0].ReplacementModule != "example.com/specific" {
		t.Fatalf("%+v", r)
	}
}

func TestReplacementSelectionRetainsExactPrecedenceAndEvidence(t *testing.T) {
	for _, tc := range []struct{ replacements, kind, module, version, source string }{
		{
			replacements: "replace example.com/dep => example.com/remote v1.2.0\n",
			kind:         "module",
			module:       "example.com/remote",
			version:      "v1.2.0",
			source:       "replace example.com/dep => example.com/remote v1.2.0",
		},
		{
			replacements: "replace example.com/dep v1.0.0 => example.com/exact v1.2.0\nreplace example.com/dep => ./local\n",
			kind:         "module",
			module:       "example.com/exact",
			version:      "v1.2.0",
			source:       "replace example.com/dep v1.0.0 => example.com/exact v1.2.0",
		},
		{
			replacements: "replace example.com/dep => example.com/remote v1.1.0\nreplace example.com/dep v1.0.0 => ./local\n",
			kind:         "local-unresolved",
			module:       "",
			version:      "",
			source:       "replace example.com/dep v1.0.0 => ./local",
		},
	} {
		text := "module example.com/root\nrequire example.com/dep v1.0.0\nrequire example.com/unrelated v1.0.0\n" + tc.replacements
		docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("go.mod", []byte(text), false)})
		r := dependencies.Collect(context.Background(), docs)
		if len(r.Declarations) != 2 {
			t.Fatalf("inventory dropped declarations: %+v", r)
		}
		d := r.Declarations[0]
		if d.Replacement != tc.kind || d.ReplacementModule != tc.module || d.ReplacementVersion != tc.version || d.ReplacementSource == nil {
			t.Fatalf("wrong replacement: %+v", d)
		}
		source := d.ReplacementSource
		if text[source.ByteStart:source.ByteEnd] != tc.source {
			t.Fatalf("replacement evidence: %q", text[source.ByteStart:source.ByteEnd])
		}
		if r.Declarations[1].Replacement != "none" || r.Declarations[1].ReplacementSource != nil {
			t.Fatal("replacement crossed module identity")
		}
	}
}

func BenchmarkGoReplacementInventory(b *testing.B) {
	for _, count := range []int{512, 1024, 2048} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			var text strings.Builder
			text.WriteString("module example.com/root\nrequire (\n")
			for i := range count {
				if _, err := fmt.Fprintf(&text, "example.com/m%04d v1.0.0\n", i); err != nil {
					b.Error(err)
				}
			}
			text.WriteString(")\nreplace (\n")
			for i := range count {
				if _, err := fmt.Fprintf(&text, "example.com/m%04d => ./local\n", i); err != nil {
					b.Error(err)
				}
			}
			text.WriteString(")\n")
			docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("go.mod", []byte(text.String()), false)})
			if r := dependencies.Collect(context.Background(), docs); len(r.Declarations) != count {
				b.Fatalf("incomplete benchmark: %d", len(r.Declarations))
			}
			b.ResetTimer()
			for range b.N {
				_ = dependencies.Collect(context.Background(), docs)
			}
		})
	}
}

func TestReplacementIndexPreservesCancelledInventory(t *testing.T) {
	text := "module example.com/root\nrequire example.com/dep v1.0.0\nreplace example.com/dep => ./local\n"
	docs := document.PrepareAll(context.Background(), []artifact.File{artifact.NewFile("go.mod", []byte(text), false)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := dependencies.Collect(ctx, docs)
	if len(r.Declarations) != 0 || len(r.Manifests) != 1 || r.Manifests[0].Status != "cancelled" {
		t.Fatalf("cancelled inventory published replacement evidence: %+v", r)
	}
}
