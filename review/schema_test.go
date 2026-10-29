package review_test

import (
	"encoding/json"
	"testing"

	"github.com/skarm/scout/review"
)

// The schema is sent to providers, while Go enforces these limits locally.
// Inspect its decoded wire shape to catch drift between the two boundaries.
func TestResponseSchemaUsesProtocolLimits(t *testing.T) {
	raw, err := json.Marshal(review.ResponseSchema())
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Enum     []string `json:"enum"`
			MaxItems int      `json:"maxItems"`
		} `json:"properties"`
		Definitions map[string]struct {
			MaxItems int `json:"maxItems"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	version := schema.Properties["schema_version"].Enum
	if len(version) != 1 || version[0] != review.ProtocolVersion {
		t.Fatalf("schema version %v does not match %q", version, review.ProtocolVersion)
	}
	for _, name := range []string{"proposals", "assessments"} {
		if got := schema.Properties[name].MaxItems; got != review.MaxItems {
			t.Errorf("%s limit = %d, want %d", name, got, review.MaxItems)
		}
	}
	if got := schema.Definitions["evidence"].MaxItems; got != review.MaxEvidence {
		t.Errorf("evidence limit = %d, want %d", got, review.MaxEvidence)
	}
}
