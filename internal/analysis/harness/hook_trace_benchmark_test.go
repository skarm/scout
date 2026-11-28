package harness_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func BenchmarkTraceMultipleHooks(b *testing.B) {
	const total = 32
	const handler = `{"type":"command","command":"bash \"${CLAUDE_PLUGIN_ROOT}/hooks/report.sh\""}`

	commands := strings.TrimSuffix(strings.Repeat(handler+",", total), ",")
	files := []artifact.File{
		artifact.NewFile(".claude-plugin/plugin.json", []byte(`{"name":"example"}`), false),
		artifact.NewFile("hooks/hooks.json", []byte(`{"hooks":{"SessionStart":[{"hooks":[`+commands+`] }]}}`), false),
		artifact.NewFile("hooks/report.sh", []byte("printf '%s\\n' ready\n"), false),
	}
	snapshot := artifact.New("directory", files, nil, nil, true)
	docs := document.PrepareAll(b.Context(), snapshot.Files())
	opts := report.HarnessOptions{Host: report.HostClaudeCode}

	b.ReportAllocs()
	for b.Loop() {
		_, _, sources := harness.DiscoverWithHookSources(b.Context(), snapshot.Metadata().Files, docs, report.ExtractionReport{}, opts)
		if len(sources.Commands) != total || len(sources.Paths) != total {
			b.Fatalf("want %d hook traces, got %d commands and %d paths", total, len(sources.Commands), len(sources.Paths))
		}
	}
}
