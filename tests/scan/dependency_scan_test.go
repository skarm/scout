package scout_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
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

func TestClassifiedDependenciesPolicyEvidenceAndFormats(t *testing.T) {
	queried := time.Now().UTC().Add(-time.Minute)
	source := report.AdvisorySource{Name: "operator-intel", URL: "https://example.invalid/intel/MAL-fixture", Revision: "snapshot-1"}
	malicious := osv.ID{ID: "MAL-fixture", Kind: report.AdvisoryMaliciousPackage, Source: source, Modified: queried.Add(-time.Nanosecond).Format(time.RFC3339Nano)}
	for _, tc := range []struct {
		name, manifest, rule string
		version              int
		advisories           []osv.ID
		age                  time.Duration
		missing              bool
		incomplete           bool
		decision             report.Decision
		code                 int
	}{
		{name: "malicious", version: 2, advisories: []osv.ID{malicious}, rule: "MAL001", decision: report.Block, code: 1},
		{name: "prefix-only", version: 1, advisories: []osv.ID{{ID: "MAL-fixture"}}, rule: "OSV001", decision: report.Allow},
		{name: "explicit-vulnerability", version: 2, advisories: []osv.ID{{ID: "MAL-fixture", Kind: "vulnerability"}}, rule: "OSV001", decision: report.Allow},
		{name: "negative", version: 2, advisories: []osv.ID{}, decision: report.Allow},
		{name: "missing", version: 2, missing: true, incomplete: true, decision: report.Review, code: 2},
		{name: "stale", version: 2, advisories: []osv.ID{}, age: -8 * 24 * time.Hour, incomplete: true, decision: report.Review, code: 2},
		{name: "unresolved", version: 2, advisories: []osv.ID{malicious}, manifest: "sample>=1.2.3\n", incomplete: true, decision: report.Review, code: 2},
		{name: "positive-and-gap", version: 2, advisories: []osv.ID{malicious}, manifest: "sample==1.2.3\nother==2.0.0\n", rule: "MAL001", incomplete: true, decision: report.Block, code: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			config.Gate = policy.Options{Scope: policy.SelectedScope, FailAt: report.Critical}
			options := osv.DefaultOptions()
			options.Enabled = true
			cache := osv.Cache{Version: tc.version, QueriedAt: queried.Add(tc.age), Records: []osv.Record{}}
			if !tc.missing {
				cache.Records = append(cache.Records, osv.Record{Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: tc.advisories})
			}
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
			manifest := tc.manifest
			if manifest == "" {
				manifest = "sample==1.2.3\n"
			}
			result, err := scanner.ScanBytes(t.Context(), "requirements-dev.txt", []byte(manifest))
			if errors.Is(err, scantest.ErrIncomplete) != tc.incomplete || err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatalf("unexpected scan error: %v", err)
			}
			if scantest.ExitCode(result) != tc.code || result.Evaluation.Decision != tc.decision || (result.Run.State == report.RunComplete) == tc.incomplete {
				t.Fatalf("state=%s decision=%s code=%d diagnostics=%+v", result.Run.State, result.Evaluation.Decision, scantest.ExitCode(result), result.Diagnostics)
			}
			if result.Vulnerabilities.ClassifiedCache != (tc.version == 2) || (len(result.Findings) == 1) != (tc.rule != "") || len(result.Findings) > 1 {
				t.Fatalf("classification or unexpected findings: %+v %+v", result.Vulnerabilities, result.Findings)
			}
			if tc.rule == "" {
				return
			}
			f := result.Findings[0]
			if f.RuleID != tc.rule || len(f.AdvisoryIDs) != 1 || f.AdvisoryIDs[0] != "MAL-fixture" || f.Location.ByteStart < 0 || f.Location.ByteEnd > len(manifest) || f.Location.ByteEnd <= f.Location.ByteStart {
				t.Fatalf("wrong rule or source range: %+v", f)
			}
			spanHash := sha256.Sum256([]byte(manifest)[f.Location.ByteStart:f.Location.ByteEnd])
			fileHash := sha256.Sum256([]byte(manifest))
			if f.Evidence.SpanSHA256 != hex.EncodeToString(spanHash[:]) || f.Evidence.FileSHA256 != hex.EncodeToString(fileHash[:]) {
				t.Fatal("advisory is not bound to captured manifest bytes")
			}
			if tc.rule != "MAL001" {
				if f.Severity != report.High {
					t.Fatalf("unclassified ID promoted to malware: %+v", f)
				}
				return
			}
			v := result.Vulnerabilities.Matches[0]
			cacheHash := sha256.Sum256(options.Offline)
			if f.Severity != report.Critical || v.Kind != report.AdvisoryMaliciousPackage || v.Source != source || v.DatabaseModified != malicious.Modified || result.Vulnerabilities.DatabaseSHA256 != hex.EncodeToString(cacheHash[:]) {
				t.Fatalf("lost classified advisory evidence: %+v", v)
			}
			for _, format := range []report.Format{report.JSON, report.SARIF, report.Text, report.Markdown} {
				var out bytes.Buffer
				if err := report.Write(&out, format, result.Document); err != nil {
					t.Fatal(err)
				}
				for _, required := range []string{"MAL001", "MAL-fixture", source.Name, source.URL, source.Revision, malicious.Modified} {
					if !strings.Contains(out.String(), required) {
						t.Fatalf("%s lost %q", format, required)
					}
				}
				if format == report.JSON {
					var decoded report.Document
					if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
						t.Fatal(err)
					}
					if err := decoded.Validate(); err != nil {
						t.Fatal(err)
					}
					decoded.Run.Targets[0].Analysis.Vulnerabilities.Matches[0].Source.Revision = "tampered"
					if decoded.Validate() == nil {
						t.Fatal("provenance change did not invalidate the run digest")
					}
				}
			}
		})
	}
}

func TestAdvisoryCoverageCountsDeclarationsAndFiles(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	malicious := []osv.ID{{ID: "MAL-fixture", Kind: report.AdvisoryMaliciousPackage, Modified: at.Add(-time.Hour).Format(time.RFC3339), Source: report.AdvisorySource{Name: "operator-intel", URL: "https://example.invalid/MAL-fixture", Revision: "snapshot-1"}}}
	for _, tc := range []struct {
		name, rule, extra string
		advisories        []osv.ID
		count             int
		gap, limited      bool
	}{
		{name: "malicious", rule: "MAL001", count: 2, advisories: malicious},
		{name: "ordinary", rule: "OSV001", count: 2, advisories: []osv.ID{{ID: "GHSA-fixture"}}},
		{name: "negative", rule: "MAL001", advisories: []osv.ID{}},
		{name: "missing-coordinate", rule: "MAL001", count: 2, advisories: malicious, extra: "other==2.0.0\n", gap: true},
		{name: "partial-manifest", rule: "MAL001", count: 2, advisories: malicious, extra: "--unsupported-option\n", gap: true},
		{name: "retention-limit", rule: "MAL001", count: 2, advisories: malicious, limited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := scantest.DefaultConfig()
			config.Gate.Scope = policy.SelectedScope
			retained := tc.count
			if tc.limited {
				config.Scanner.Limits.Retention.MaxFindings = 1
				retained = 1
			}
			o := osv.DefaultOptions()
			o.Enabled = true
			o.Offline, _ = json.Marshal(osv.Cache{Version: 2, QueriedAt: at, Records: []osv.Record{{Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: tc.advisories}}})
			config.Scanner.Vulnerabilities = &o
			scanner, err := scantest.New(config, t)
			if err != nil {
				t.Fatal(err)
			}
			result, err := scanner.ScanBytes(t.Context(), "requirements-dev.txt", []byte("sample==1.2.3\nsample==1.2.3\n"+tc.extra))
			if len(result.Findings) != retained || errors.Is(err, scantest.ErrIncomplete) != (tc.gap || tc.limited) || err != nil && !errors.Is(err, scantest.ErrIncomplete) {
				t.Fatalf("scan failed: findings=%d error=%v", len(result.Findings), err)
			}
			done, status := 1, report.OutcomeCompleted
			if tc.gap {
				done, status = 0, report.OutcomePartial
			}
			var found bool
			for _, check := range result.Coverage.Checks {
				if check.AnalyzerID == tc.rule {
					found = true
					if check.Findings != tc.count || check.FilesTotal != 1 || check.FilesDone != done || check.Status != status {
						t.Errorf("coverage does not describe observed declarations and completed file: %+v", check)
					}
				}
			}
			if !found {
				t.Fatal("selected advisory coverage is missing")
			}
		})
	}
}

func TestCachedAdvisoriesParticipateInComparison(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	for _, version := range []int{1, 2} {
		for _, direction := range []string{"introduced", "not_observed", "gap"} {
			t.Run(string(rune('0'+version))+"/"+direction, func(t *testing.T) {
				advisory := osv.ID{ID: "GHSA-fixture"}
				if version == 2 {
					advisory = osv.ID{ID: "MAL-fixture", Kind: report.AdvisoryMaliciousPackage, Modified: at.Add(-time.Hour).Format(time.RFC3339), Source: report.AdvisorySource{Name: "operator-intel", URL: "https://example.invalid/MAL-fixture", Revision: "snapshot-1"}}
				}
				config := scantest.DefaultConfig()
				config.Gate.Scope = policy.SelectedScope
				o := osv.DefaultOptions()
				o.Enabled = true
				o.Offline, _ = json.Marshal(osv.Cache{Version: version, QueriedAt: at, Records: []osv.Record{
					{Ecosystem: "PyPI", Name: "sample", Version: "1.2.2", Vulnerabilities: []osv.ID{}},
					{Ecosystem: "PyPI", Name: "sample", Version: "1.2.3", Vulnerabilities: []osv.ID{advisory}},
				}})
				config.Scanner.Vulnerabilities = &o
				scanner, err := scantest.New(config, t)
				if err != nil {
					t.Fatal(err)
				}
				before, after := t.TempDir(), t.TempDir()
				old, next := "sample==1.2.2\n", "sample==1.2.3\nsample==1.2.3\n"
				switch direction {
				case "not_observed":
					old, next = next, old
				case "gap":
					old += "other==2.0.0\n"
				}
				scenario.WriteFile(t, before, "requirements-dev.txt", old)
				scenario.WriteFile(t, after, "requirements-dev.txt", next)
				result, err := scanner.Compare(t.Context(), before, after, scantest.DefaultCompareOptions())
				if direction == "gap" {
					if !errors.Is(err, scantest.ErrIncomplete) || result.Run.State != report.RunIncomplete || result.Run.Comparison.Completeness != report.Partial {
						t.Fatalf("comparison hid a coordinate gap: %+v error=%v", result.Run.Comparison, err)
					}
					return
				}
				if err != nil || result.Run.State != report.RunComplete || result.Run.Comparison.Completeness != report.Complete {
					t.Fatalf("complete cache answers treated as unchecked: %+v error=%v", result.Run.Comparison, err)
				}
				if len(result.Run.Comparison.Findings) != 2 {
					t.Fatalf("duplicate source observations were collapsed: %+v", result.Run.Comparison.Findings)
				}
				for _, change := range result.Run.Comparison.Findings {
					if change.Change != direction {
						t.Fatalf("unexpected cached advisory delta: %+v", change)
					}
				}
			})
		}
	}
}
