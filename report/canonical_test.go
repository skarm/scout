package report_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/skarm/scout/report"
)

// This wire oracle pins compatibility with the original digest contract. The
// production path works directly from concrete Go values instead of this tree.
func TestConcreteCanonicalDigestMatchesWireContract(t *testing.T) {
	for _, message := range []string{"ordinary", "<tag>&\u2028\u2029", "Привет🙂\x00", string([]byte{0xff, 'x'})} {
		run := runFixture()
		run.Targets[0].Analysis.Findings[0].Message = message
		got, err := report.SealRun(run)
		if err != nil {
			t.Fatal(err)
		}
		run.Digest = ""
		for i := range run.Targets {
			run.Targets[i].Label = ""
			run.Targets[i].Analysis.Source = nil
			run.Targets[i].Analysis.Vulnerabilities.QueriedAt = ""
		}
		encoded, err := json.Marshal(run)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		value = canonicalOracle(value, "")
		encoded, err = json.Marshal(struct {
			Operation report.Operation `json:"operation"`
			Run       any              `json:"run"`
		}{Operation: run.Operation, Run: value})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		if want := "sha256:" + hex.EncodeToString(digest[:]); got.Digest != want {
			t.Fatalf("canonical wire drift for %q: got %s want %s", message, got.Digest, want)
		}
	}
}

func canonicalOracle(value any, field string) any {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			node[key] = canonicalOracle(child, key)
		}
	case []any:
		for i, child := range node {
			node[i] = canonicalOracle(child, "")
		}
		if unorderedOracle(field) {
			sort.Slice(node, func(i, j int) bool {
				a, _ := json.Marshal(node[i])
				b, _ := json.Marshal(node[j])
				return bytes.Compare(a, b) < 0
			})
		}
	case nil:
		if unorderedOracle(field) {
			return []any{}
		}
	}
	return value
}

func unorderedOracle(field string) bool {
	switch field {
	case "findings", "observations", "diagnostics", "rules", "checks", "files", "skills", "objects", "skipped", "plugins", "components", "edges", "references", "issues", "requirements", "outcomes", "proposals", "assessments", "proposal_assessments", "queries", "matches", "aliases", "dependency_ids", "context_signals", "signature_names", "related_evidence", "contexts", "manifests", "declarations", "assets", "prompts", "link_ids", "finding_ids", "proposal_ids", "knowledge_topic_ids", "sources", "reasons", "problems", "suppressed":
		return true
	default:
		return false
	}
}
