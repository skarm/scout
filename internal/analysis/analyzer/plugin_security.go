// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted detector concepts from SkillSpector mcp_tool_poisoning and
// mcp_least_privilege. Modified bounded parser/evidence implementation.

package analyzer

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/dependencies"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

var (
	hiddenMetadata  = regexp.MustCompile(`(?is)<\\?!-{2}.*?-{2}>|\[//\]:\s*#\s*\([^\r\n]*\)|data:text/[^;,\s]{1,80};base64,`)
	base64Metadata  = regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`)
	poisonParameter = regexp.MustCompile(`(?i)\b(?:ignore|override)\b.{0,80}\b(?:instructions?|system|rules?)\b|\bsystem\s*:|\b(?:send|upload|transmit)\b.{0,80}\b(?:credentials?|token|secret|conversation)\b|\b(?:curl|wget|eval|exec)\s*\(?`)
)

//nolint:gochecknoglobals // Immutable package-name dictionaries shared by concurrent scans.
var (
	popularPython    = strings.Fields("requests numpy pandas flask django pytest sqlalchemy pillow cryptography boto3 pyyaml beautifulsoup4 scipy matplotlib setuptools urllib3 certifi click fastapi pydantic aiohttp httpx rich typer openai anthropic langchain transformers torch tensorflow")
	popularNPM       = strings.Fields("express react lodash axios chalk commander debug dotenv moment typescript webpack eslint prettier next vite zod uuid ws yargs minimist glob semver async underscore bluebird mongoose mongodb redis socket.io nodemon jest mocha chai")
	historicalPython = map[string]bool{"pycrypto": true, "nose": true, "distribute": true}
	historicalNPM    = map[string]bool{"request": true, "nomnom": true, "optimist": true, "npm-conf": true}
)

// Metadata fields carry roles. Each selected rule owns one text predicate;
// traversal and evidence projection are shared across those independent rules.
//
//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var metadataTextPolicies = map[string]func(string, bool, bool) bool{
	ruleNVTP1: func(value string, _, _ bool) bool { return hiddenText(value) },
	ruleNVTP2: func(value string, identifier, _ bool) bool { return identifier && confusingIdentifier(value) },
	ruleNVTP3: func(value string, _, parameter bool) bool {
		return parameter && (poisonParameter.MatchString(value) || len([]rune(value)) > 500)
	},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	historicalPackages = map[string]map[string]bool{report.EcosystemPyPI: historicalPython, report.EcosystemNPM: historicalNPM}
	popularPackages    = map[string][]string{report.EcosystemPyPI: popularPython, report.EcosystemNPM: popularNPM}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var invisibleMetadataRunes = &unicode.RangeTable{R16: []unicode.Range16{
	{Lo: 0x200b, Hi: 0x200d, Stride: 1}, {Lo: 0x202a, Hi: 0x202e, Stride: 1}, {Lo: 0x2066, Hi: 0x2069, Stride: 1}, {
		Lo:     0xfeff,
		Hi:     0xfeff,
		Stride: 1,
	},
}}

type pluginCheck struct{ id string }

type dependencySignal struct{ id string }

func PluginSecurityRules() []Analyzer {
	out := append([]Analyzer{
		pluginCheck{id: ruleNVTP1},
		pluginCheck{id: ruleNVTP2},
		pluginCheck{id: ruleNVTP3},
		permissionCheck{id: ruleNVLP1},
		permissionCheck{id: ruleNVLP2},
		permissionCheck{id: ruleNVLP3},
		permissionCheck{id: ruleNVLP4},
		uninspectedReference{},
		dependencySignal{id: ruleNVSC5},
		dependencySignal{id: ruleNVSC6},
		sourceRedirection{},
		triggerCheck{id: ruleNVTR1M},
		triggerCheck{id: ruleNVTR2M},
		triggerCheck{id: ruleNVTR3M},
	}, deserializationRules()...)

	return append(out, RegistryRules()...)
}

func (a pluginCheck) Rule() report.Rule {
	title := "Suspicious hidden content in tool metadata"
	if a.id == ruleNVTP2 {
		title = "Confusable or invisible tool identifier"
	}

	if a.id == ruleNVTP3 {
		title = "Suspicious parameter description or default"
	}

	return report.Rule{
		ID:          a.id,
		Version:     "2",
		Title:       title,
		Description: title,
		Severity:    report.Medium,
		Category:    "tool-poisoning",
		Method:      "structured-metadata-heuristic",
		Limitation:  "Adapted TP1-TP3. Parsed metadata only; hidden text, confusables and long descriptions are review signals, not proof of malice. Legitimate defaults can match. Unknown schemas/Unicode scripts remain unverified.",
	}
}

func (a pluginCheck) AppliesTo(f document.File) bool { return hasParsedUnit[parse.JSONTree](f) }

func (a pluginCheck) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	var out Result

	seen := map[source.Span]bool{}
	ops := 0

	for _, u := range f.Units() {
		t, ok := u.Tree.(parse.JSONTree)
		if !ok || t.Root == nil {
			continue
		}

		emit := pluginEmitter(u, &out, seen, budget)
		check := a.pluginTextCheck(emit)
		a.walkMetadata(ctx, t.Root, 0, &ops, &out, check, emit)
	}

	if ops >= 32768 {
		return out, errors.New("metadata operation limit")
	}

	return out, ctx.Err()
}

func pluginEmitter(u document.Unit, out *Result, seen map[source.Span]bool, budget int) func(*jsonconfig.Node) {
	return func(n *jsonconfig.Node) {
		if n == nil {
			return
		}

		p, e := u.View.Original(n.Span)
		if e != nil {
			return
		}

		if seen[p] {
			return
		}

		seen[p] = true

		if len(out.Matches) >= budget {
			out.Truncated = true
			return
		}

		out.Matches = append(out.Matches, Match{Start: p.Start, End: p.End})
	}
}

func (a pluginCheck) pluginTextCheck(emit func(*jsonconfig.Node)) func(*jsonconfig.Node, bool, bool) {
	policy := metadataTextPolicies[a.id]

	return func(node *jsonconfig.Node, identifier, parameter bool) {
		if text, known := node.Text(); known && policy != nil && policy(text, identifier, parameter) {
			emit(node)
		}
	}
}

func (a pluginCheck) walkMetadata(ctx context.Context, n *jsonconfig.Node, depth int, ops *int, out *Result, check func(*jsonconfig.Node, bool, bool), emit func(*jsonconfig.Node)) {
	for entry := range configurationNodes(ctx, n, 32-depth, configurationForward) {
		if out.Truncated || *ops >= 32768 {
			return
		}

		*ops++

		if entry.depth+depth > 32 || entry.node.Kind != jsonconfig.KindObject {
			continue
		}

		node := entry.node
		check(node.Get("name"), true, false)
		check(node.Get("description"), false, false)

		for _, trigger := range node.GetOrEmpty("triggers").Elements {
			check(trigger, true, false)
		}

		for _, parameter := range node.GetOrEmpty("parameters").Elements {
			check(parameter.Get("name"), true, true)
			check(parameter.Get("description"), false, true)
			check(parameter.Get("default"), false, true)
		}

		a.checkToolProperties(node, check, emit)
	}
}

func (a pluginCheck) checkToolProperties(n *jsonconfig.Node, check func(*jsonconfig.Node, bool, bool), emit func(*jsonconfig.Node)) {
	props := n.Get("inputSchema").Get("properties")
	if props == nil {
		props = n.Get("input_schema").Get("properties")
	}

	if props != nil {
		for _, m := range props.Members {
			key := &jsonconfig.Node{Kind: jsonconfig.KindString, String: m.Key, Span: m.KeySpan}
			check(key, true, false)
			check(m.Value.Get("description"), false, true)
			d := m.Value.Get("default")
			check(d, false, true)

			if a.id == ruleNVTP3 {
				if s, ok := d.Text(); ok && strings.HasPrefix(strings.ToLower(s), "http://") {
					emit(d)
				}
			}
		}
	}
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

func invisibleMetadata(text string) bool {
	return strings.ContainsFunc(text, func(char rune) bool { return unicode.Is(invisibleMetadataRunes, char) })
}

func confusingIdentifier(s string) bool {
	if invisibleMetadata(s) {
		return true
	}

	latin, other := false, false

	for _, r := range s {
		if unicode.In(r, unicode.Latin) {
			latin = true
		}

		if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
			other = true
		}
	}

	return latin && other // Natural-language non-Latin descriptions are not identifiers.
}

func hiddenText(s string) bool {
	if hiddenMetadata.MatchString(s) || invisibleMetadata(s) {
		return true
	}

	for _, candidate := range base64Metadata.FindAllString(s, 8) {
		b, e := base64.StdEncoding.DecodeString(candidate + strings.Repeat("=", (4-len(candidate)%4)%4))
		if e == nil && len(b) > 0 && utf8.Valid(b) {
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
