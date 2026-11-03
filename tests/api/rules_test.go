package scout_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/rulepack"
)

func TestPublishedCatalogDescribesSelectedChecks(t *testing.T) {
	all := map[string]scantest.Rule{}
	for _, rule := range scantest.Rules(true) {
		if _, exists := all[rule.ID]; exists || rule.ID == "" {
			t.Fatalf("duplicate or empty rule: %q", rule.ID)
		}
		all[rule.ID] = rule
	}
	for _, name := range []string{"basic", "extended"} {
		t.Run(name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			if name == "extended" {
				config = scantest.FullConfig()
			}
			missing := name == "extended" && (!frontend.BackendFor("python").Available || !signatures.Backend().Available)
			scanner, err := scantest.New(config, t)
			if missing {
				if err == nil {
					if err := scanner.Close(); err != nil {
						t.Error(err)
					}
					t.Fatal("unavailable required backend accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			report, err := scanner.ScanBytes(context.Background(), "notes.txt", []byte("Public documentation."))
			if err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatal(err)
			}
			selected := map[string]scantest.Rule{}
			for _, rule := range report.Rules {
				if !reflect.DeepEqual(all[rule.ID], rule) {
					t.Fatalf("published descriptor disagrees with executed check %q", rule.ID)
				}
				selected[rule.ID] = rule
			}
			if name == "basic" {
				if len(selected) != len(scantest.Rules(false)) {
					t.Fatal("basic catalog differs from selected check set")
				}
				for _, rule := range scantest.Rules(false) {
					if !reflect.DeepEqual(selected[rule.ID], rule) {
						t.Fatalf("basic descriptor disagrees with executed check %q", rule.ID)
					}
				}
			}
		})
	}
}

func TestPublishedCatalogCannotChangeLaterScans(t *testing.T) {
	original := scantest.Rules(true)
	changed := scantest.Rules(true)
	for i := range changed {
		changed[i].ID = "caller-controlled"
		if g := changed[i].Guidance; g != nil {
			g.Explanation = "caller-controlled"
			if len(g.ReviewChecks) > 0 {
				g.ReviewChecks[0] = "caller-controlled"
			}
			if len(g.Sources) > 0 {
				g.Sources[0].URL = "caller-controlled"
			}
		}
	}
	if !reflect.DeepEqual(original, scantest.Rules(true)) {
		t.Fatal("published catalog mutated trusted descriptors")
	}
}

func TestVersionedRulepackArtifactContract(t *testing.T) {
	rules := []byte(`rule pack_fixture { meta: category="malware" strings: $marker="RULEPACK_SENTINEL_001" condition: $marker }`)
	data, err := rulepack.Create("team/agent", "1.2.3", rules)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	pin := hex.EncodeToString(digest[:])
	selection, err := rulepack.Parse(data, pin)
	if err != nil || selection.Identity.ID != "team/agent" || selection.Identity.Version != "1.2.3" || selection.Identity.ABI != report.RulepackABI || selection.Identity.SHA256 != pin || !bytes.Equal(selection.Rules, rules) {
		t.Fatalf("artifact identity or source lost: %+v error=%v", selection, err)
	}
	again, err := rulepack.Create("team/agent", "1.2.3", rules)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatal("artifact creation is not deterministic")
	}
	selection.Rules[0] = '!'
	fresh, err := rulepack.Parse(data, pin)
	if err != nil || !bytes.Equal(fresh.Rules, rules) {
		t.Fatal("parsed source aliases artifact or another selection")
	}
	newVersion, err := rulepack.Create("team/agent", "1.2.4", rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rulepack.Parse(newVersion, pin); err == nil {
		t.Fatal("pin did not bind package version metadata")
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"schema", func(d map[string]any) { d["schema"] = "scout.rulepack/v2" }},
		{"abi", func(d map[string]any) { d["abi"] = "scout.yara-source/v2" }},
		{"empty-id", func(d map[string]any) { d["id"] = "" }},
		{"long-id", func(d map[string]any) { d["id"] = strings.Repeat("x", 161) }},
		{"control-version", func(d map[string]any) { d["version"] = "PRIVATE\nVERSION" }},
		{"source-null", func(d map[string]any) { d["yara"] = nil }},
		{"source-modified", func(d map[string]any) { d["yara"].(map[string]any)["source"] = "PRIVATE_SOURCE" }},
		{"source-empty", func(d map[string]any) { d["yara"].(map[string]any)["source"] = "" }},
		{"source-hash", func(d map[string]any) { d["yara"].(map[string]any)["sha256"] = strings.Repeat("z", 64) }},
		{"unknown-field", func(d map[string]any) { d["download"] = "https://example.invalid/PRIVATE" }},
		{"unknown-source-field", func(d map[string]any) { d["yara"].(map[string]any)["include"] = "PRIVATE" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			tc.edit(doc)
			raw, _ := json.Marshal(doc)
			if _, err := rulepack.Parse(raw, ""); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("invalid metadata accepted or disclosed: %v", err)
			}
		})
	}
	for _, raw := range [][]byte{
		nil, []byte("null"), append(bytes.Clone(data), []byte("{}")...),
		[]byte(strings.Replace(string(data), `"id":`, `"ID":`, 1)),
		[]byte(strings.Replace(string(data), `"id":`, `"id":"other","id":`, 1)),
		[]byte(strings.Replace(string(data), `"sha256":`, `"SHA256":`, 1)),
		[]byte(strings.Repeat("x", rulepack.MaxBytes+1)),
	} {
		if _, err := rulepack.Parse(raw, ""); err == nil {
			t.Fatal("ambiguous, trailing or oversized artifact accepted")
		}
	}
	for _, source := range [][]byte{nil, {0xff}, bytes.Repeat([]byte("x"), rulepack.MaxRulesBytes+1)} {
		if _, err := rulepack.Create("team/agent", "1", source); err == nil {
			t.Fatal("invalid source encoding or size accepted")
		}
	}
}

func TestVersionedRulepackScannerEvidenceAndOwnership(t *testing.T) {
	rules := []byte(`// PRIVATE_SOURCE_NOT_REPORT_CONTENT
rule pack_fixture { meta: category="malware" strings: $marker="RULEPACK_SENTINEL_001" condition: $marker }`)
	data, err := rulepack.Create("team/agent", "1.2.3", rules)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	config := scantest.DefaultConfig()
	config.Gate.Scope = policy.SelectedScope
	config.Scanner.Checks.YARA = true
	config.Scanner.Signatures.Rulepack = data
	config.Scanner.Signatures.RulepackSHA256 = hex.EncodeToString(digest[:])
	scanner, err := scantest.New(config, t)
	if !signatures.Backend().Available {
		if err == nil {
			t.Fatal("versioned rules silently accepted without required backend")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x'
	}
	first, err := scanner.ScanBytes(t.Context(), "inert.txt", []byte("RULEPACK_SENTINEL_001"))
	if err != nil || len(first.Findings) != 1 || first.Findings[0].RuleID != "YR1" || first.Evaluation.Decision != report.Block {
		t.Fatalf("versioned source not applied: findings=%+v error=%v", first.Findings, err)
	}
	identity := first.Signatures.Rulepack
	if identity == nil || identity.ID != "team/agent" || identity.Version != "1.2.3" || identity.SHA256 != hex.EncodeToString(digest[:]) || first.Findings[0].Evidence.SpanSHA256 == "" {
		t.Fatal("missing selected package identity or captured evidence")
	}
	for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
		var out bytes.Buffer
		if err := report.Write(&out, format, first.Document); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "team/agent") || !strings.Contains(out.String(), "1.2.3") || !strings.Contains(out.String(), identity.SHA256) || strings.Contains(out.String(), "PRIVATE_SOURCE_NOT_REPORT_CONTENT") {
			t.Fatalf("%s lost identity or exposed source", format)
		}
		if format == report.JSON {
			var document report.Document
			if err := json.Unmarshal(out.Bytes(), &document); err != nil || document.Validate() != nil {
				t.Fatal("package-backed report did not round trip", err)
			}
			document.Run.Targets[0].Analysis.Signatures.Rulepack.Version = "changed"
			if document.Validate() == nil {
				t.Fatal("package identity is not bound to the run digest")
			}
		}
	}
	identity.Version = "caller-poison"
	second, err := scanner.ScanBytes(t.Context(), "inert.txt", []byte("RULEPACK_SENTINEL_001"))
	if err != nil || second.Signatures.Rulepack.Version != "1.2.3" {
		t.Fatal("published identity can change later scans", err)
	}
	updated, err := rulepack.Create("team/agent", "1.2.4", rules)
	if err != nil {
		t.Fatal(err)
	}
	config.Scanner.Signatures.Rulepack, config.Scanner.Signatures.RulepackSHA256 = updated, ""
	updatedScanner, err := scantest.New(config, t)
	if err != nil {
		t.Fatal(err)
	}
	updatedResult, err := updatedScanner.ScanBytes(t.Context(), "inert.txt", []byte("RULEPACK_SENTINEL_001"))
	if err != nil || updatedResult.Run.Engine.RulepackDigest == second.Run.Engine.RulepackDigest || updatedResult.Signatures.RulesSHA256 != second.Signatures.RulesSHA256 {
		t.Fatal("version metadata is not pinned separately from identical signature source", err)
	}
}

func TestRulepackSelectionRejectsInvalidConfiguration(t *testing.T) {
	data, err := rulepack.Create("team/agent", "1.2.3", []byte(`rule fixture { strings: $s="marker" condition:$s }`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*scantest.Config)
	}{
		{"empty-artifact", func(c *scantest.Config) { c.Scanner.Signatures.Rulepack = []byte{}; c.Scanner.Checks.YARA = false }},
		{"pin-without-artifact", func(c *scantest.Config) {
			c.Scanner.Signatures.Rulepack = nil
			c.Scanner.Signatures.RulepackSHA256 = strings.Repeat("a", 64)
		}},
		{"pin-mismatch", func(c *scantest.Config) { c.Scanner.Signatures.RulepackSHA256 = strings.Repeat("a", 64) }},
		{"disabled-backend", func(c *scantest.Config) { c.Scanner.Checks.YARA = false }},
		{"unversioned-conflict", func(c *scantest.Config) { c.Scanner.Signatures.ExtraRules = []byte("rule other { condition:true }") }},
		{"invalid-artifact", func(c *scantest.Config) { c.Scanner.Signatures.Rulepack = []byte("PRIVATE_INVALID_JSON") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			config.Scanner.Checks.YARA = true
			config.Scanner.Signatures.Rulepack = data
			tc.edit(&config)
			if scanner, err := scantest.New(config, t); err == nil || scanner != nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("invalid package configuration accepted or disclosed: %v", err)
			}
		})
	}
	if !signatures.Backend().Available {
		return
	}
	for _, rules := range []string{`rule invalid { condition: ??? }`, `include "PRIVATE_FILE.yar"`, `import "console" rule console_output { condition: console.log("PRIVATE") }`} {
		artifact, err := rulepack.Create("team/agent", "1.2.3", []byte(rules))
		if err != nil {
			t.Fatal(err)
		}
		config := scantest.DefaultConfig()
		config.Scanner.Checks.YARA = true
		config.Scanner.Signatures.Rulepack = artifact
		if scanner, err := scantest.New(config, t); err == nil || scanner != nil {
			t.Fatal("package bypassed native source restrictions")
		}
	}
}

func TestVersionedRulepackComparisonRecognizesCompletedSignatures(t *testing.T) {
	if !signatures.Backend().Available {
		t.Skip("signature comparison requires native backend")
	}
	rules := []byte(`rule compare_marker { meta: category="malware" strings: $marker="RULEPACK_COMPARE_SENTINEL" condition:$marker }`)
	artifact, err := rulepack.Create("team/agent", "1.2.3", rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, versioned := range []bool{false, true} {
		config := scantest.DefaultConfig()
		config.Gate.Scope = policy.SelectedScope
		config.Scanner.Checks.YARA = true
		if versioned {
			config.Scanner.Signatures.Rulepack = artifact
		} else {
			config.Scanner.Signatures.ExtraRules = rules
		}
		scanner, err := scantest.New(config, t)
		if err != nil {
			t.Fatal(err)
		}
		before, after := t.TempDir(), t.TempDir()
		scenario.WriteFile(t, before, "input.txt", "ordinary public documentation")
		scenario.WriteFile(t, after, "input.txt", "RULEPACK_COMPARE_SENTINEL")
		for _, introduced := range []bool{true, false} {
			old, next, change := before, after, "introduced"
			if !introduced {
				old, next, change = after, before, "not_observed"
			}
			document, err := scanner.Compare(t.Context(), old, next, scantest.DefaultCompareOptions())
			if err != nil || document.Run.State != report.RunComplete || document.Run.Comparison.Completeness != report.Complete || len(document.Run.Comparison.Findings) != 1 || document.Run.Comparison.Findings[0].Change != change {
				t.Fatalf("completed signature coverage not recognized: versioned=%v change=%s delta=%+v error=%v", versioned, change, document.Run.Comparison, err)
			}
		}
	}
}

func TestRulepackCreationBoundsRejectedMetadataAllocations(t *testing.T) {
	// The invalid string belongs to the caller; rejection must not make an
	// encoded artifact-sized copy of it before enforcing the metadata limits.
	large := strings.Repeat("x", 8<<20)
	for _, field := range []string{"id", "version"} {
		t.Run(field, func(t *testing.T) {
			id, version := "team/agent", "1.2.3"
			if field == "id" {
				id = large
			} else {
				version = large
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			data, err := rulepack.Create(id, version, []byte("rule x { condition:true }"))
			runtime.ReadMemStats(&after)
			if err == nil || len(data) != 0 {
				t.Fatal("oversized metadata accepted")
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4*rulepack.MaxBytes {
				t.Fatalf("metadata limit enforced after allocating %d bytes", allocated)
			}
		})
	}
}
