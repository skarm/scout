package metadata_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/skarm/scout/internal/analysis/metadata"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestRecordLimitIncludesParsedFallbackAndMixedMetadata(t *testing.T) {
	for _, kind := range []string{"parsed", "fallback", "mixed"} {
		for _, count := range []int{512, 513} {
			t.Run(fmt.Sprintf("%s/%d", kind, count), func(t *testing.T) {
				docs := metadataLimitDocuments(kind, count)
				r := metadata.Collect(context.Background(), docs, "auto")
				want := report.Complete
				if count > 512 {
					want = report.Partial
				}
				if len(r.Files) != min(count, 512) || r.Completeness != want {
					t.Fatalf("records=%d completeness=%s; want %d %s", len(r.Files), r.Completeness, min(count, 512), want)
				}
				for i, f := range r.Files {
					if f.Path != docs[i].Artifact().Metadata().Path {
						t.Fatalf("accepted metadata order changed at %d: %s", i, f.Path)
					}
				}
			})
		}
	}
}

func TestCancellationRetainsAcceptedMixedMetadata(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := metadata.Collect(&metadataCancelContext{Context: ctx, cancel: cancel, remaining: 3}, metadataLimitDocuments("mixed", 8), "auto")
	if len(r.Files) != 3 || r.Completeness != report.Partial {
		t.Fatalf("accepted metadata was not retained on cancellation: records=%d completeness=%s", len(r.Files), r.Completeness)
	}
}

func metadataLimitDocuments(kind string, count int) []document.File {
	files := make([]artifact.File, count)
	for i := range files {
		name, text := fmt.Sprintf("metadata/m%d/plugin.json", i), `{"name":"sample"}`
		if kind == "fallback" || kind == "mixed" && i%2 == 0 {
			name, text = fmt.Sprintf("skills/s%d/SKILL.md", i), "# No frontmatter\n"
		}
		files[i] = artifact.NewFile(name, []byte(text), false)
	}
	return document.PrepareAll(context.Background(), files)
}

type metadataCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *metadataCancelContext) Err() error {
	if c.remaining == 0 {
		c.cancel()
	}
	c.remaining--
	return c.Context.Err()
}
