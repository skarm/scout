// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified SC9: Scout inventories excluded directories too; this signal is
// source-bound to a local declaration whose implementation was not captured.

package analyzer

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var uncapturedLocalReasons = stringSet("handler_not_captured component_not_captured")

type (
	uninspectedReference struct{ records map[string][]Match }
	referenceIdentity    struct{ path, digest string }
)

func BindGraph(checks []Analyzer, docs []document.File, g report.ComponentGraph) []Analyzer {
	records := map[string][]Match{}

	captured := map[referenceIdentity]bool{}
	for _, d := range docs {
		captured[referenceIdentity{path: d.Artifact().Metadata().Path, digest: d.Artifact().Metadata().SHA256}] = true
	}

	for _, r := range g.References {
		if r.Source == nil || r.Status != "unresolved" || !uncapturedLocalReasons[r.Reason] {
			continue
		}

		s := r.Source

		if !captured[referenceIdentity{path: s.Path, digest: s.SHA256}] {
			continue
		}

		records[s.Path] = append(records[s.Path], Match{Start: s.ByteStart, End: s.ByteEnd})
	}

	out := append([]Analyzer(nil), checks...)
	for i, a := range out {
		if _, ok := a.(uninspectedReference); ok {
			out[i] = uninspectedReference{records: records}
		}
	}

	return out
}

func (uninspectedReference) Rule() report.Rule {
	return report.Rule{
		ID:          ruleNVSC9,
		Version:     "1",
		Title:       "Declared local component was not inspected",
		Description: "A captured configuration refers to a local component or handler unavailable to inspection.",
		Severity:    report.High,
		Category:    "supply-chain",
		Method:      "source-bound-component-coverage",
		Limitation:  "Selected harness local references only. Missing, excluded and unreadable targets cannot be distinguished universally; this is an inspection obligation, not proof of malicious code. All captured directories remain inspected without path exemptions.",
	}
}

func (a uninspectedReference) AppliesTo(f document.File) bool {
	return len(a.records[f.Artifact().Metadata().Path]) > 0
}

func (a uninspectedReference) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	out := Result{}

	for _, m := range a.records[f.Artifact().Metadata().Path] {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}

		if len(out.Matches) >= budget {
			out.Truncated = true
			break
		}

		out.Matches = append(out.Matches, m)
	}

	return out, nil
}
