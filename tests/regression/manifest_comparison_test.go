package scout_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

func TestManifestUpdateSignalsRetainSourceAndPolicy(t *testing.T) {
	for _, tc := range []struct{ name, old, next, id, decision string }{
		{
			name:     "permissions",
			old:      `{"permissions":["read"]}`,
			next:     `{"permissions":["read","network"]}`,
			id:       "NV-RP1",
			decision: "block",
		},
		{
			name:     "triggers",
			old:      `{"triggers":["format"]}`,
			next:     `{"triggers":["all prompts"]}`,
			id:       "NV-RP2",
			decision: "review",
		},
		{
			name:     "numeric-default",
			old:      `{"parameters":{"budget":{"type":"number","default":1}}}`,
			next:     `{"parameters":{"budget":{"type":"number","default":2}}}`,
			id:       "NV-RP3",
			decision: "review",
		},
		{
			name:     "string-default",
			old:      `{"parameters":{"token":{"type":"string","default":"PRIVATE_SENTINEL_A"}}}`,
			next:     `{"parameters":{"token":{"type":"string","default":"PRIVATE_SENTINEL_B"}}}`,
			id:       "NV-RP3",
			decision: "review",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, next := t.TempDir(), t.TempDir()
			scenario.WriteFile(t, before, "manifest.json", tc.old)
			scenario.WriteFile(t, next, "manifest.json", tc.next)
			r, e := scenario.Scanner(t, scantest.DefaultConfig()).Compare(context.Background(), before, next, scantest.DefaultCompareOptions())
			if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
				t.Fatal(e)
			}
			found := false
			for _, signal := range r.Run.Comparison.ManifestSignals {
				if signal.RuleID == tc.id {
					found = true
					if signal.Before == nil || signal.After == nil || signal.Before.SpanSHA256 == "" || signal.After.SpanSHA256 == "" {
						t.Fatal("missing evidence")
					}
				}
			}
			if !found || string(r.Evaluation.Decision) != tc.decision {
				t.Fatalf("%+v %+v", r.Run.Comparison.ManifestSignals, r.Evaluation)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "PRIVATE_SENTINEL") {
				t.Fatal("parameter default leaked")
			}
		})
	}
}

func TestManifestUpdateIgnoresSetAndObjectOrdering(t *testing.T) {
	before, next := t.TempDir(), t.TempDir()
	scenario.WriteFile(t, before, "manifest.json", `{"permissions":["read","network"],"triggers":["a","b"],"parameters":{"x":{"type":"number","default":1}}}`)
	scenario.WriteFile(t, next, "manifest.json", `{"parameters":{"x":{"default":1.0,"type":"number"}},"triggers":["b","a"],"permissions":["network","read"]}`)
	r, e := scenario.Scanner(t, scantest.DefaultConfig()).Compare(context.Background(), before, next, scantest.DefaultCompareOptions())
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
		t.Fatal(e)
	}
	if len(r.Run.Comparison.ManifestSignals) > 0 {
		t.Fatal("formatting became rug-pull", r.Run.Comparison.ManifestSignals)
	}
}
