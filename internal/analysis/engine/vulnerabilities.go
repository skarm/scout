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
	Version:     "1",
	Title:       "Known vulnerability for an exact declared package coordinate",
	Description: "The explicitly selected database reported an advisory for the captured exact package version.",
	Severity:    report.High,
	Category:    "known-vulnerable-dependency",
	Method:      "exact-coordinate-vulnerability-lookup",
	Limitation:  "Database match is not proof of installation, reachability or exploitability. Range-only and unresolved Go MVS versions are not queried.",
})

// VulnerabilityRule returns a copy for rule-catalog inspection without network access.
func VulnerabilityRule() report.Rule { return report.CloneRule(vulnerabilityRule) }

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

	r.Rules = append(r.Rules, report.CloneRule(vulnerabilityRule))
	byID := map[string]report.Dependency{}
	byPath := map[string]document.File{}

	for _, d := range r.Dependencies.Declarations {
		byID[d.ID] = d
	}

	for _, d := range docs {
		byPath[d.Artifact().Metadata().Path] = d
	}

	collectVulnerabilityFindings(r, byID, byPath, collector)

	if r.Vulnerabilities.Completeness != report.Complete {
		r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
			Code:         "vulnerability_incomplete",
			Message:      "Some requested dependency coordinates, pages or database results are unresolved; see per-query outcomes.",
			AffectsScope: true,
		})
	}

	applyVulnerabilityCoverage(r, byID)
}

func applyVulnerabilityCoverage(r *report.Analysis, byID map[string]report.Dependency) {
	fc := map[string]*report.FileCoverage{}
	for i := range r.Coverage.Files {
		fc[r.Coverage.Files[i].Path] = &r.Coverage.Files[i]
	}

	for _, q := range r.Vulnerabilities.Queries {
		if d, ok := byID[q.DependencyID]; ok {
			if f := fc[d.Source.Path]; f != nil {
				f.Checks = append(f.Checks, report.FileCheck{AnalyzerID: ruleOSV001, Status: q.Status})
				if q.Status != report.OutcomeCompleted && q.Status != report.OutcomeCached {
					f.Gaps = append(f.Gaps, "OSV001:"+q.Status)
				}
			}
		}
	}

	status := report.OutcomeCompleted
	if r.Vulnerabilities.Completeness != report.Complete {
		status = report.OutcomePartial
	}

	r.Coverage.Checks = append(r.Coverage.Checks, report.Check{
		AnalyzerID: ruleOSV001,
		Version:    "1",
		Status:     status,
		FilesTotal: len(r.Dependencies.Manifests),
		Findings:   len(r.Vulnerabilities.Matches),
		Detail:     "Per-coordinate plan and outcomes are in vulnerabilities.queries; not every declaration has an exact version.",
	})
}

func collectVulnerabilityFindings(r *report.Analysis, byID map[string]report.Dependency, byPath map[string]document.File, collector *findingCollector) {
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

			f, e := makeFinding(vulnerabilityRule, doc, check.Match{Start: d.Source.ByteStart, End: d.Source.ByteEnd})
			if e != nil {
				r.Vulnerabilities.Completeness = report.Partial
				continue
			}

			f.ID = artifact.Hash([]byte(f.ID + "\x00" + v.ID))
			f.AdvisoryIDs = []string{v.ID}
			collector.add(f)
		}
	}
}
