package scout_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/skarm/scout/internal/scantest"
	scenario "github.com/skarm/scout/internal/scantest/scenarios"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestGoModuleDeclarationsAndNoResolution(t *testing.T) {
	root := t.TempDir()
	text := `module example.com/skill

go 1.23
require (
 example.com/original v1.2.3
 example.com/local v1.0.0 // indirect
)
replace example.com/original => example.com/fork v1.2.4
replace example.com/local => ../DO_NOT_OPEN
`
	scenario.WriteFile(t, root, "go.mod", text)
	r, scanErr18 := scenario.Scan(t, root)
	if scanErr18 != nil && !errors.Is(scanErr18, scantest.ErrIncomplete) {
		t.Fatal(scanErr18)
	}
	if errors.Is(scanErr18, scantest.ErrIncomplete) && r.Run.State == "complete" {
		t.Fatal("incomplete error with a complete run")
	}

	if !scenario.HasRule(r, "SC002") || !scenario.HasRule(r, "SC003") || len(r.Dependencies.Declarations) != 2 || r.Coverage.Completeness != "complete" || r.Evaluation.Decision != "review" {
		t.Fatalf("findings=%+v deps=%+v", r.Findings, r.Dependencies)
	}
	for _, d := range r.Dependencies.Declarations {
		if d.VersionSemantics != "declared-minimum-unresolved-MVS" || d.Source.ByteStart < 0 || d.Source.ByteEnd > len(text) || d.ID == "" {
			t.Fatal(d)
		}
		if d.Module == "example.com/original" && (d.ReplacementModule != "example.com/fork" || d.ReplacementVersion != "v1.2.4") {
			t.Fatal(d)
		}
	}
	data, _ := json.Marshal(r)
	if bytes.Contains(data, []byte("DO_NOT_OPEN")) {
		t.Fatal("replacement path leaked as report source excerpt")
	}
}

func TestOSVExactCacheIntegratesEvidenceAndPolicy(t *testing.T) {
	c := scantest.DefaultConfig()
	vulnerabilities := osv.DefaultOptions()
	c.Scanner.Vulnerabilities = &vulnerabilities
	c.Scanner.Vulnerabilities.Enabled = true
	cache := osv.Cache{
		Version:   1,
		QueriedAt: time.Now().UTC(),
		Records: []osv.Record{{
			Ecosystem:       "npm",
			Name:            "sample",
			Version:         "1.2.3",
			Vulnerabilities: []osv.ID{{ID: "GHSA-fixture-only"}},
		}},
	}
	c.Scanner.Vulnerabilities.Offline, _ = json.Marshal(cache)
	s, e := scantest.New(c, t)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.ScanBytes(context.Background(), "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/sample":{"version":"1.2.3"}}}`))
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
		t.Fatal(e)
	}
	if r.Evaluation.Decision != "block" || len(r.Vulnerabilities.Matches) != 1 {
		t.Fatalf("%+v %+v", r.Evaluation, r.Vulnerabilities)
	}
	var found bool
	for _, f := range r.Findings {
		if f.RuleID == "OSV001" {
			found = true
			if len(f.AdvisoryIDs) != 1 || f.Evidence.SpanSHA256 == "" {
				t.Fatal("missing advisory evidence")
			}
		}
	}
	if !found {
		t.Fatal("missing OSV finding")
	}
	// Minimum/range declarations cannot be upgraded to exact installed versions.
	r, e = s.ScanBytes(context.Background(), "package.json", []byte(`{"dependencies":{"sample":"1.2"}}`))
	if e != nil && !errors.Is(e, scantest.ErrIncomplete) {
		t.Fatal(e)
	}
	if len(r.Vulnerabilities.Matches) > 0 || r.Vulnerabilities.Completeness == report.Complete {
		t.Fatal("range got an exact CVE result")
	}
}

func TestOSVFreshCacheCompletesScan(t *testing.T) {
	for _, tc := range []struct {
		name       string
		advisories []osv.ID
		decision   report.Decision
		code       int
	}{
		{name: "clean", advisories: []osv.ID{}, decision: report.Allow, code: 0},
		{name: "vulnerable", advisories: []osv.ID{{ID: "GHSA-fixture-only"}}, decision: report.Block, code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			config.Gate.Scope = policy.SelectedScope
			options := osv.DefaultOptions()
			options.Enabled = true
			cache := osv.Cache{Version: 1, QueriedAt: time.Now().UTC(), Records: []osv.Record{{
				Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: tc.advisories,
			}}}
			var err error
			options.Offline, err = json.Marshal(cache)
			if err != nil {
				t.Fatal(err)
			}
			config.Scanner.Vulnerabilities = &options
			scanner, err := scantest.New(config, t)
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.ScanBytes(t.Context(), "requirements-dev.txt", []byte("sample==1.2.3\n"))
			if err != nil || result.Run.State != report.RunComplete || result.Coverage.Completeness != report.Complete {
				t.Fatalf("fresh exact cache caused an incomplete scan: state=%s coverage=%s diagnostics=%+v error=%v", result.Run.State, result.Coverage.Completeness, result.Diagnostics, err)
			}
			if len(result.Vulnerabilities.Queries) != 1 || result.Vulnerabilities.Queries[0].Status != report.OutcomeCached || result.Evaluation.Decision != tc.decision || scantest.ExitCode(result) != tc.code {
				t.Fatalf("cached observation lost policy or query outcome: %+v %+v", result.Vulnerabilities, result.Evaluation)
			}
		})
	}
}
