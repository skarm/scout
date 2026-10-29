// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted dependency-name heuristics with bounded, captured-source evidence.

package analyzer

import (
	"context"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Immutable package-name dictionaries shared by concurrent scans.
var (
	popularPython    = strings.Fields("requests numpy pandas flask django pytest sqlalchemy pillow cryptography boto3 pyyaml beautifulsoup4 scipy matplotlib setuptools urllib3 certifi click fastapi pydantic aiohttp httpx rich typer openai anthropic langchain transformers torch tensorflow")
	popularNPM       = strings.Fields("express react lodash axios chalk commander debug dotenv moment typescript webpack eslint prettier next vite zod uuid ws yargs minimist glob semver async underscore bluebird mongoose mongodb redis socket.io nodemon jest mocha chai")
	historicalPython = map[string]bool{"pycrypto": true, "nose": true, "distribute": true}
	historicalNPM    = map[string]bool{"request": true, "nomnom": true, "optimist": true, "npm-conf": true}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	historicalPackages = map[string]map[string]bool{report.EcosystemPyPI: historicalPython, report.EcosystemNPM: historicalNPM}
	popularPackages    = map[string][]string{report.EcosystemPyPI: popularPython, report.EcosystemNPM: popularNPM}
)

type dependencySignal struct{ id string }

func DependencyRules() []Analyzer {
	return []Analyzer{dependencySignal{id: ruleNVSC5}, dependencySignal{id: ruleNVSC6}, sourceRedirection{}}
}

func (a dependencySignal) Rule() report.Rule {
	title := "Dependency name matches a historical maintenance concern list"
	limit := "Small historical list adapted from upstream; not a current maintainer-status database or proof of vulnerability."

	if a.id == ruleNVSC6 {
		title = "Dependency name resembles a popular package"
		limit = "Selected popular-package lexicon and bounded edit distance. Similarity is not proof of typosquatting or compromise."
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       title,
		Description: title,
		Severity:    report.Medium,
		Category:    "supply-chain",
		Method:      "parsed-dependency-name-heuristic",
		Limitation:  limit,
	}
}

func (dependencySignal) AppliesTo(document.File) bool { return true }

func (a dependencySignal) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	inv := dependencies.Collect(ctx, []document.File{f})
	out := Result{}
	collected := collectMatches(&out, budget)

	for _, d := range inv.Declarations {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}

		match := a.matchesDependencyName(d.Ecosystem, d.Module)

		at := source.Span{Start: d.Source.ByteStart, End: d.Source.ByteEnd}
		if match && !collected.span(at.Start, at.End) {
			break
		}
	}

	return out, nil
}

func (a dependencySignal) matchesDependencyName(ecosystem, name string) bool {
	if a.id == ruleNVSC5 {
		return historicalPackages[ecosystem][name]
	}

	popular := popularPackages[ecosystem]
	if slices.Contains(popular, name) {
		return false
	}

	for _, candidate := range popular {
		distance := editDistance(name, candidate)
		if distance > 0 && distance <= 2 && distance*3 <= min(len(name), len(candidate)) {
			return true
		}
	}

	return false
}

func editDistance(a, b string) int {
	if len(a) > 64 || len(b) > 64 {
		return 65
	}

	prev := make([]int, len(b)+1)
	for i := range prev {
		prev[i] = i
	}

	for i := 1; i <= len(a); i++ {
		next := make([]int, len(b)+1)
		next[0] = i

		for j := 1; j <= len(b); j++ {
			c := 0
			if a[i-1] != b[j-1] {
				c = 1
			}

			next[j] = min(next[j-1]+1, prev[j]+1, prev[j-1]+c)
		}

		prev = next
	}

	return prev[len(b)]
}
