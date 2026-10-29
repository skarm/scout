// Package update compares fresh observations. Admission policy belongs to Gate.
package update

import (
	"context"
	"errors"

	"github.com/skarm/scout/report"
)

const (
	algorithmVersion = "2"
	maxOperations    = 2_000_000
)

type builder struct {
	ctx                          context.Context
	before, after                report.Analysis
	options                      report.UpdateOptions
	delta                        report.UpdateDelta
	old, next                    inventory
	oldComponents, newComponents componentIndex
	issues                       map[string]bool
	retained, operations         int
	stopped                      bool
}

// Comparable fingerprints pin every option that controls an observation.
type comparisonContract struct {
	schema, engine, rulepackDigest, profile, host string
	legacyRulesVersion                            string
	limits, extraction, analysisLimits, rules     string
	semantic                                      bool
	semanticOptions, provider                     string
}

// Build returns only a source-bound delta. It never computes, copies or applies
// admission policy, and it cannot suppress any candidate finding.
func Build(ctx context.Context, before, after report.Analysis, options report.UpdateOptions) (report.UpdateDelta, error) {
	if ctx == nil {
		return report.UpdateDelta{}, errors.New("nil comparison context")
	}

	if err := options.Validate(); err != nil {
		return report.UpdateDelta{}, err
	}

	b := builder{
		ctx:     ctx,
		before:  before,
		after:   after,
		options: options,
		issues:  map[string]bool{},
		delta: report.UpdateDelta{
			AlgorithmVersion: algorithmVersion,
			Completeness:     report.Complete,
			Files:            []report.FileChange{},
			Components:       []report.ComponentChange{},
			Dependencies:     []report.DependencyChange{},
			Findings:         []report.FindingChange{},
			Issues:           []string{},
		},
	}
	if !sameContract(before, after) {
		b.issue("comparison_contract_mismatch")
	}

	single := standalone(before) && standalone(after)

	b.old, b.next = b.inventory(before, single), b.inventory(after, single)
	if !b.old.complete {
		b.issue("previous_inventory_incomplete")
	}

	if !b.next.complete {
		b.issue("candidate_inventory_incomplete")
	}

	b.delta.SameSnapshot = before.Artifact.InventoryComplete && after.Artifact.InventoryComplete && before.Artifact.SnapshotSHA256 != "" && before.Artifact.SnapshotSHA256 == after.Artifact.SnapshotSHA256
	b.files()
	b.oldComponents, b.newComponents = b.components(before, b.old), b.components(after, b.next)
	b.componentChanges()
	b.dependencies()
	b.findings()
	b.manifests()

	return b.delta, ctx.Err()
}

func sameContract(before, after report.Analysis) bool {
	return before.SchemaVersion != "" && contract(before) == contract(after)
}

func contract(r report.Analysis) comparisonContract {
	return comparisonContract{
		schema:             r.SchemaVersion,
		engine:             r.EngineVersion,
		rulepackDigest:     r.RulepackDigest,
		profile:            r.Profile,
		host:               r.Components.RequestedHost,
		legacyRulesVersion: r.RulesVersion,
		limits:             digest(r.Limits),
		extraction:         digest(r.Extraction.Limits),
		analysisLimits:     digest(r.AnalysisLimits),
		rules:              digest(r.Rules),
		semantic:           r.Semantic.Enabled,
		semanticOptions:    digest(r.Semantic.Options),
		provider:           digest(r.Semantic.Provider),
	}
}

func (b *builder) issue(code string) {
	if b.issues[code] {
		return
	}

	b.issues[code] = true
	b.delta.Issues = append(b.delta.Issues, code)
	b.delta.Completeness = report.Partial
}

func (b *builder) step() bool {
	if b.stopped {
		return false
	}

	if b.ctx.Err() != nil {
		b.issue("comparison_cancelled")
		b.stopped = true

		return false
	}

	b.operations++
	if b.operations > maxOperations {
		b.issue("comparison_operation_limit")
		b.stopped = true

		return false
	}

	return true
}

func (b *builder) retain() bool {
	if b.retained >= b.options.MaxChanges {
		b.delta.OmittedChanges++
		b.issue("comparison_change_limit")

		return false
	}

	b.retained++

	return true
}
