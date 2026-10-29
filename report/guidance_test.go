package report_test

import (
	"testing"

	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

func TestWithGuidanceCopiesOperatorDescriptors(t *testing.T) {
	g := knowledge.Guide{
		Explanation:          "original",
		ReviewChecks:         []string{"original"},
		BenignConsiderations: []string{"original"},
		Sources:              []knowledge.Reference{{Symbol: "original"}},
	}
	original := report.Rule{ID: "custom", Guidance: &g}
	copied := knowledge.WithGuidance(original)
	copied.Guidance.Explanation = "different"
	copied.Guidance.ReviewChecks[0] = "different"
	copied.Guidance.Sources[0].Symbol = "different"
	if g.Explanation != "original" || g.ReviewChecks[0] != "original" || g.Sources[0].Symbol != "original" {
		t.Fatal("operator rule aliased")
	}
}
