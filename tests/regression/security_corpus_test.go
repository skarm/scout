package scout_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
)

// This is an authored regression corpus, not an independent holdout and not a
// measurement of an actual LLM. Known blind spots are explicitly separate from
// benign cases, so "no static signal" cannot be misreported as correct security.
func TestSecurityRegressionCorpus(t *testing.T) {
	data, err := os.ReadFile("../../testdata/security-corpus/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
		Cases         []struct {
			ID       string   `json:"id"`
			Category string   `json:"category"`
			Label    string   `json:"label"`
			Path     string   `json:"path"`
			Content  string   `json:"content"`
			Expected []string `json:"expected_rules"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || corpus.Kind != "authored_regression_not_holdout" || len(corpus.Cases) == 0 {
		t.Fatal("wrong corpus contract")
	}
	labels := map[string]int{}
	ids := map[string]bool{}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			if ids[tc.ID] || tc.ID == "" || tc.Category == "" {
				t.Fatal("invalid case identity")
			}
			ids[tc.ID] = true
			switch tc.Label {
			case "signal", "benign", "ambiguous", "known_static_gap":
			default:
				t.Fatal("unknown label")
			}
			labels[tc.Label]++
			root := t.TempDir()
			scenario.WriteFile(t, root, tc.Path, tc.Content)
			got, scanErr35 := scenario.Scan(t, root)
			if scanErr35 != nil && !errors.Is(scanErr35, scantest.ErrIncomplete) {
				t.Fatal(scanErr35)
			}
			if errors.Is(scanErr35, scantest.ErrIncomplete) && got.Run.State == "complete" {
				t.Fatal("incomplete error with a complete run")
			}

			rules := make([]string, 0)
			seen := map[string]bool{}
			for _, f := range got.Findings {
				if !seen[f.RuleID] {
					rules = append(rules, f.RuleID)
					seen[f.RuleID] = true
				}
			}
			sort.Strings(rules)
			sort.Strings(tc.Expected)
			if !reflect.DeepEqual(rules, tc.Expected) {
				t.Fatalf("label=%s got=%v expected=%v", tc.Label, rules, tc.Expected)
			}
			if tc.Label == "ambiguous" && got.Evaluation.Decision == "block" {
				t.Fatal("text signal alone treated as proven maliciousness")
			}
			if (tc.Label == "signal" || tc.Label == "ambiguous") && got.Evaluation.Decision != "review" {
				t.Fatal("signal must require review")
			}
			if got.Semantic.Enabled {
				t.Fatal("static corpus unexpectedly invokes a model")
			}
		})
	}
	t.Logf("Authored regression: signal=%d benign=%d ambiguous=%d; known static gaps=%d (not successes, not live semantic evaluation)", labels["signal"], labels["benign"], labels["ambiguous"], labels["known_static_gap"])
}
