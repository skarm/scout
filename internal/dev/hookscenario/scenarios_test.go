package hookscenario_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/dev/hookscenario"
	"github.com/skarm/scout/report"
)

func TestAnalyzeRejectsUnpinnedSource(t *testing.T) {
	t.Parallel()

	input := map[string]map[string]string{
		"hook-09": {"hooks/stop-hook.sh": "#!/bin/bash\nexit 0\n"},
	}
	results := hookscenario.Analyze(t.Context(), input)
	if len(results) != 7 {
		t.Fatalf("got %d scenario results, want 7", len(results))
	}

	for _, result := range results {
		if result.Coverage.Completeness != report.Partial || !strings.Contains(result.Problem, "SHA-256 mismatch") ||
			len(result.ReachedLines) != 0 {
			t.Errorf("unexpected coverage for unverified scenario %+v", result)
		}
	}
}
