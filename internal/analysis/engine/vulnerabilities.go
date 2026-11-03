package engine

import (
	"context"
	"time"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Immutable rule template; callers receive deep copies through VulnerabilityRule.
var vulnerabilityRule = knowledge.WithGuidance(report.Rule{
	ID:          ruleOSV001,
	Version:     "2",
	Title:       "Known vulnerability for an exact declared package coordinate",
	Description: "The explicitly selected database reported an advisory for the captured exact package version.",
	Severity:    report.High,
	Category:    "known-vulnerable-dependency",
	Method:      "exact-coordinate-vulnerability-lookup",
	Limitation:  "Database match is not proof of installation, reachability or exploitability. Range-only and unresolved Go MVS versions are not queried.",
})

//nolint:gochecknoglobals // Immutable rule template; AdvisoryRules returns independent copies.
var maliciousPackageRule = knowledge.WithGuidance(report.Rule{
	ID:          ruleMAL001,
	Version:     "1",
	Title:       "Known malicious package at an exact declared coordinate",
	Description: "An explicitly trusted version-2 cache classifies the captured exact package version as malicious and retains its source and modification time.",
	Severity:    report.Critical,
	Category:    "known-malicious-dependency",
	Method:      "exact-coordinate-malicious-package-cache",
	Limitation:  "Operator-supplied provenance is an assertion, not source authentication or proof of installation/execution. Only explicit classified cache records apply; advisory ID prefixes, names and ordinary querybatch responses do not establish malware. Missing/stale coordinates and unresolved versions remain gaps.",
})

// VulnerabilityRule returns a copy for rule-catalog inspection without network access.
func VulnerabilityRule() report.Rule { return report.CloneRule(vulnerabilityRule) }

// AdvisoryRules describes both classifications without reading a cache or contacting a service.
func AdvisoryRules() []report.Rule {
	return []report.Rule{VulnerabilityRule(), report.CloneRule(maliciousPackageRule)}
}

func selectedAdvisoryRules(classified bool) []report.Rule {
	if classified {
		return AdvisoryRules()
	}

	return []report.Rule{VulnerabilityRule()}
}

func advisoryRule(v report.Vulnerability) report.Rule {
	if v.Kind == report.AdvisoryMaliciousPackage {
		return maliciousPackageRule
	}

	return vulnerabilityRule
}

func applyVulnerabilities(ctx context.Context, r *report.Analysis, docs []document.File, o osv.Options, collector *findingCollector) {
	v, err := osv.Check(ctx, r.Dependencies, o, time.Now())

	r.Vulnerabilities = v
	if err != nil {
		r.Vulnerabilities.Completeness = report.Failed
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "vulnerability_failed",
			Message:      "Requested vulnerability lookup failed; no clean result can be inferred.",
			AffectsScope: true,
		})
	}

	if !o.Enabled {
		return
	}

	r.Rules = append(r.Rules, selectedAdvisoryRules(v.ClassifiedCache)...)
	byID := map[string]report.Dependency{}
	byPath := map[string]document.File{}

	for _, d := range r.Dependencies.Declarations {
		byID[d.ID] = d
	}

	for _, d := range docs {
		byPath[d.Artifact().Metadata().Path] = d
	}

	counts := collectVulnerabilityFindings(r, byID, byPath, collector)

	if r.Vulnerabilities.Completeness != report.Complete {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "vulnerability_incomplete",
			Message:      "Some requested dependency coordinates, pages or database results are unresolved; see per-query outcomes.",
			AffectsScope: true,
		})
	}

	applyVulnerabilityCoverage(r, byID, counts)
}

func applyVulnerabilityCoverage(r *report.Analysis, byID map[string]report.Dependency, counts map[string]int) {
	rules := selectedAdvisoryRules(r.Vulnerabilities.ClassifiedCache)

	done := map[string]bool{}

	for _, manifest := range r.Dependencies.Manifests {
		if manifest.InventoryComplete() {
			done[manifest.Path] = true
		}
	}

	fc := map[string]*report.FileCoverage{}
	for i := range r.Coverage.Files {
		fc[r.Coverage.Files[i].Path] = &r.Coverage.Files[i]
	}

	for _, q := range r.Vulnerabilities.Queries {
		if d, ok := byID[q.DependencyID]; ok {
			if q.Status != report.OutcomeCompleted && q.Status != report.OutcomeCached {
				delete(done, d.Source.Path)
			}

			if f := fc[d.Source.Path]; f != nil {
				for _, rule := range rules {
					f.Checks = append(f.Checks, report.FileCheck{AnalyzerID: rule.ID, Status: q.Status})
					if q.Status != report.OutcomeCompleted && q.Status != report.OutcomeCached {
						f.Gaps = append(f.Gaps, rule.ID+":"+q.Status)
					}
				}
			}
		}
	}

	status := report.OutcomeCompleted
	if r.Vulnerabilities.Completeness != report.Complete {
		status = report.OutcomePartial
	}

	for _, rule := range rules {
		r.Coverage.Checks = append(r.Coverage.Checks, report.Check{
			AnalyzerID: rule.ID,
			Version:    rule.Version,
			Status:     status,
			FilesTotal: len(r.Dependencies.Manifests),
			Findings:   counts[rule.ID],
			FilesDone:  len(done),
			Detail:     "Shared exact-coordinate plan is in vulnerabilities.queries; MAL001 requires explicitly classified cache metadata, not an ID prefix.",
		})
	}
}

func collectVulnerabilityFindings(r *report.Analysis, byID map[string]report.Dependency, byPath map[string]document.File, collector *findingCollector) map[string]int {
	counts := map[string]int{}

	for _, v := range r.Vulnerabilities.Matches {
		for _, id := range v.DependencyIDs {
			d, ok := byID[id]
			if !ok {
				r.Vulnerabilities.Completeness = report.Partial
				continue
			}

			doc, ok := byPath[d.Source.Path]
			if !ok {
				r.Vulnerabilities.Completeness = report.Partial
				continue
			}

			f, e := makeFinding(advisoryRule(v), doc, check.Match{Start: d.Source.ByteStart, End: d.Source.ByteEnd})
			if e != nil {
				r.Vulnerabilities.Completeness = report.Partial
				continue
			}

			f.ID = artifact.Hash([]byte(f.ID + "\x00" + v.ID))
			f.AdvisoryIDs = []string{v.ID}
			collector.add(f)
			counts[f.RuleID]++
		}
	}

	return counts
}
