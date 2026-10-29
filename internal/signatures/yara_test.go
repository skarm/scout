package signatures_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/report"
)

func TestUnavailableYARAXIsNotClean(t *testing.T) {
	if signatures.Backend().Available {
		t.Skip("native build: absence path covered by coreonly job")
	}
	o := signatures.DefaultOptions()
	o.Enabled = true
	inputs := []signatures.Input{{Path: "a", Data: "text", SHA256: digest("text")}, {
		Path:   "b",
		Data:   "two",
		SHA256: digest("two"),
	}}
	r, e := signatures.Check(context.Background(), inputs, o)
	if e != nil || r.Completeness != "partial" || len(r.Outcomes) != 2 {
		t.Fatal(r, e)
	}
	for _, v := range r.Outcomes {
		if v.Status != "unavailable" || len(v.Matches) != 0 {
			t.Fatal(v)
		}
	}
	if r.Engine.Name != "yara-x" || r.RulesSHA256 == "" {
		t.Fatal(r)
	}
}

func TestOptionsDisabledAndLegacyPaths(t *testing.T) {
	o := signatures.DefaultOptions()
	r, e := signatures.Check(context.Background(), nil, o)
	if e != nil || r.Enabled || r.Completeness != "complete" {
		t.Fatal(r, e)
	}
	for _, which := range []string{"rules", "budget"} {
		t.Run(which, func(t *testing.T) {
			p := o
			switch which {
			case "rules":
				p.ExtraRules = []byte("rule sample { condition:true }")
			case "budget":
				p.MaxFiles = 0
			}
			if p.Validate() == nil {
				t.Fatal("unsupported configuration accepted")
			}
		})
	}
}

func TestInputIdentityAndBudget(t *testing.T) {
	o := signatures.DefaultOptions()
	o.Enabled = true
	o.MaxFileBytes = 3
	r, e := signatures.Check(context.Background(), []signatures.Input{{Path: "a", Data: "1234", SHA256: digest("1234")}, {
		Path:   "b",
		Data:   "123",
		SHA256: digest("not123"),
	}}, o)
	if e != nil || r.Completeness != "partial" || r.Outcomes[0].Status != "limit" || r.Outcomes[1].Status != "invalid_input" {
		t.Fatal(r, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e = signatures.Check(ctx, []signatures.Input{{Path: "a", Data: "x", SHA256: digest("x")}}, o)
	if e == nil || r.Outcomes[0].Status != "cancelled" {
		t.Fatal(r, e)
	}
	if _, e = signatures.Check(nil, nil, o); e == nil {
		t.Fatal("nil context")
	}
}

// An external caller can still construct every public result type and assign it
// to the library report. The fixed wire sample also guards nested field names.
func TestPublicSignatureResultsPreserveAssignmentsAndJSON(t *testing.T) {
	const wire = `{"enabled":true,"engine":{"name":"yara-x","binding_version":"test-binding","native_version":"unknown","available":true},"rules_sha256":"digest","completeness":"partial","outcomes":[{"path":"input.bin","sha256":"object","status":"completed","engine_version":"test-engine","matches":[{"rule":"Example","category":"malware","spans":[{"start":1,"end":3}]}],"truncated":false}],"limitations":["test-only"]}`
	result := signatures.Report{
		Enabled: true, Engine: signatures.Capability{
			Name:           "yara-x",
			BindingVersion: "test-binding",
			NativeVersion:  "unknown",
			Available:      true,
		}, RulesSHA256: "digest", Completeness: "partial",
		Outcomes: []signatures.Outcome{{
			Path:          "input.bin",
			SHA256:        "object",
			Status:        "completed",
			EngineVersion: "test-engine",
			Matches: []signatures.Match{{
				Rule:     "Example",
				Category: "malware",
				Spans: []signatures.Span{{
					Start: 1,
					End:   3,
				}},
			}},
		}}, Limitations: []string{"test-only"},
	}
	analysis := report.Analysis{Signatures: result}
	encoded, err := json.Marshal(analysis.Signatures)
	if err != nil || string(encoded) != wire {
		t.Fatalf("signature wire contract changed: %s, %v", encoded, err)
	}
	var decoded signatures.Report
	if err := json.Unmarshal([]byte(wire), &decoded); err != nil || len(decoded.Outcomes) != 1 || len(decoded.Outcomes[0].Matches) != 1 || decoded.Outcomes[0].Matches[0].Spans[0].End != 3 {
		t.Fatalf("cannot decode existing signature result: %+v, %v", decoded, err)
	}
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
