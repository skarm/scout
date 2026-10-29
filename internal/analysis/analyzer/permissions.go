// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted LP1-LP4 concepts; immutable, namespace-scoped observations with
// captured evidence. Permission strings are declarations, never enforcement.

package analyzer

import (
	"context"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/hookpolicy"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var capPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{
		name: "shell",
		rx:   regexp.MustCompile(`(?i)subprocess|\bPopen\b|os\.(?:system|popen|exec)|exec\.Command|\b(?:curl|wget|chmod)\b`),
	},
	{
		name: "network",
		rx:   regexp.MustCompile(`(?i)\b(?:httpx|requests|urllib|aiohttp)\b|socket\.connect|\bfetch\s*\(|XMLHttpRequest|http\.(?:Get|Post|NewRequest)|\.Do\s*\(`),
	},
	{
		name: "file_read",
		rx:   regexp.MustCompile(`(?i)open\s*\([^\r\n)]{0,256},\s*['"][^'"\r\n]{0,8}r|\.(?:read_text|read_bytes)\s*\(|os\.(?:ReadFile|listdir|walk)|glob\.glob`),
	},
	{
		name: "file_write",
		rx:   regexp.MustCompile(`(?i)open\s*\([^\r\n)]{0,256},\s*['"][^'"\r\n]{0,8}[wa]|\.(?:write_text|write_bytes)\s*\(|shutil\.copy|os\.(?:WriteFile|Create|rename|mkdir)`),
	},
	{name: "env", rx: regexp.MustCompile(`(?i)os\.(?:environ|getenv|LookupEnv)|process\.env|\bdotenv\b`)},
	{name: "mcp", rx: regexp.MustCompile(`(?i)create_session|MCPClient|mcp\.client`)},
}

//nolint:gochecknoglobals // Immutable permission vocabulary shared by concurrent scans.
var (
	permissionWords      = regexp.MustCompile(`[A-Za-z_]+|\*`)
	permissionCategories = map[string]string{
		"bash":        "shell",
		"shell":       "shell",
		"execute":     "shell",
		"terminal":    "shell",
		"command":     "shell",
		"network":     "network",
		"webfetch":    "network",
		"websearch":   "network",
		"http":        "network",
		"fetch":       "network",
		"api":         "network",
		"read":        "file_read",
		"glob":        "file_read",
		"ls":          "file_read",
		"fs_read":     "file_read",
		"file_read":   "file_read",
		"write":       "file_write",
		"edit":        "file_write",
		"multiedit":   "file_write",
		"fs_write":    "file_write",
		"file_write":  "file_write",
		"env":         "env",
		"environment": "env",
		"mcp":         "mcp",
		"tools":       "mcp",
		"tool_use":    "mcp",
	}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var wildcardPermissions = stringSet("* all full any")

func PermissionRules() []Analyzer {
	return []Analyzer{permissionCheck{id: ruleNVLP1}, permissionCheck{id: ruleNVLP2}, permissionCheck{id: ruleNVLP3}, permissionCheck{id: ruleNVLP4}}
}

type permissionCheck struct {
	id      string
	records map[string]permissionRecord
	failure bool
}
type permissionRecord struct {
	span                source.Span
	present, wild, code bool
	declared            map[string]bool
	observed            map[string]report.SourceRef
}

type (
	permissionAddress = document.Address
	permissionScope   struct {
		file, ns, root string
		r              permissionRecord
	}
)

// BindContexts supplies only immutable captured scope facts, not filesystem or
// network access. The four LP rules share one bounded discovery pass per scan.
func BindContexts(ctx context.Context, checks []Analyzer, docs []document.File, extraction report.ExtractionReport) []Analyzer {
	hooks := hookpolicy.Bind(ctx, docs, extraction)

	checks = append([]Analyzer(nil), checks...)
	for i, a := range checks {
		switch v := a.(type) {
		case agentConfigCheck:
			v.hooks = hooks
			checks[i] = v
		case bundledSurface:
			v.hooks = hooks
			checks[i] = v
		}
	}

	needed := false

	for _, a := range checks {
		if _, ok := a.(permissionCheck); ok {
			needed = true
			break
		}
	}

	if !needed {
		return checks
	}

	records, failed := permissionRecords(ctx, docs, extraction)

	out := append([]Analyzer(nil), checks...)
	for i, a := range out {
		if p, ok := a.(permissionCheck); ok {
			p.records, p.failure = records, failed
			out[i] = p
		}
	}

	return out
}

func (a permissionCheck) Rule() report.Rule {
	title := map[string]string{
		ruleNVLP1: "Code capability hint lacks a matching permission declaration",
		ruleNVLP2: "Permission declaration contains a wildcard",
		ruleNVLP3: "Code capability hints have no permission declaration",
		ruleNVLP4: "Declared capability has no observed use in the captured scope",
	}[a.id]

	severity := report.Medium
	if a.id == ruleNVLP4 {
		severity = report.Low
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    "least-privilege",
		Method:      "scoped-declaration-capability-heuristic",
		Limitation:  "Captured same-namespace nearest-skill/plugin scope only. Capabilities are lexical hints, not verified execution; absence of a hint does not prove unused permission. External code, host enforcement and unknown tool names remain unverified. Related evidence contains bounded observations.",
	}
}

func (a permissionCheck) AppliesTo(f document.File) bool {
	_, ok := a.records[f.Artifact().Metadata().Path]
	return ok || a.failure
}

func (a permissionCheck) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}

	if a.failure {
		return Result{}, errors.New("permission scope discovery limited")
	}

	r, ok := a.records[f.Artifact().Metadata().Path]
	if !ok || !r.code {
		return Result{}, nil
	}

	if !r.signals()[a.id] {
		return Result{}, nil
	}

	if budget < 1 {
		return Result{Truncated: true}, nil
	}

	m := Match{Start: r.span.Start, End: r.span.End}

	keys := make([]string, 0, len(r.observed))
	for c := range r.observed {
		keys = append(keys, c)
	}

	sort.Strings(keys)

	for _, c := range keys {
		m.Related = append(m.Related, r.observed[c])
	}

	return Result{Matches: []Match{m}}, nil
}

// Permission posture compares declared and observed capability sets once per
// projection; wildcard and absent declarations remain explicit independent facts.
func (r permissionRecord) signals() map[string]bool {
	bounded := r.present && !r.wild

	return map[string]bool{
		ruleNVLP1: bounded && hasExtraPermissions(r.observed, r.declared),
		ruleNVLP2: r.wild,
		ruleNVLP3: !r.present && len(r.observed) > 0,
		ruleNVLP4: bounded && hasExtraPermissions(r.declared, r.observed),
	}
}

func hasExtraPermissions[V, W any](left map[string]V, right map[string]W) bool {
	for name := range left {
		if _, present := right[name]; !present {
			return true
		}
	}

	return false
}

func permissionRecords(ctx context.Context, docs []document.File, extraction report.ExtractionReport) (map[string]permissionRecord, bool) {
	addresses := document.CapturedAddresses(docs, extraction)

	scopes, complete := permissionScopeCandidates(ctx, docs, addresses)
	if !complete {
		return nil, true
	}

	sort.Slice(scopes, func(i, j int) bool {
		if len(scopes[i].root) != len(scopes[j].root) {
			return len(scopes[i].root) > len(scopes[j].root)
		}

		return scopes[i].file < scopes[j].file
	})

	if !observePermissionScopes(ctx, docs, addresses, scopes) {
		return nil, true
	}

	out := map[string]permissionRecord{}
	for _, s := range scopes {
		out[s.file] = s.r
	}

	return out, false
}

func permissionScopeCandidates(ctx context.Context, docs []document.File, addresses map[string]permissionAddress) ([]permissionScope, bool) {
	scopes := make([]permissionScope, 0)

	for _, doc := range docs {
		if ctx.Err() != nil {
			return nil, false
		}

		addr, known := addresses[doc.Artifact().Metadata().Path]
		if !known {
			continue
		}

		scope, candidate := permissionScopeFor(doc, addr)
		if !candidate {
			continue
		}

		if len(scopes) >= 1024 {
			return nil, false
		}

		if scope != nil {
			scopes = append(scopes, *scope)
		}
	}

	return scopes, true
}

func permissionScopeFor(d document.File, addr permissionAddress) (*permissionScope, bool) {
	isSkill := path.Base(addr.Name) == "SKILL.md"

	isPlugin := strings.HasSuffix(addr.Name, ".claude-plugin/plugin.json") || strings.HasSuffix(addr.Name, ".codex-plugin/plugin.json")
	if !isSkill && !isPlugin {
		return nil, false
	}

	record := declaredPermissionRecord(d, isSkill, isPlugin)
	if record == nil {
		return nil, true
	}

	root := path.Dir(addr.Name)
	if isPlugin {
		root = path.Dir(root)
	}

	if root == "." {
		root = ""
	}

	return &permissionScope{file: d.Artifact().Metadata().Path, ns: addr.Namespace, root: root, r: *record}, true
}

func (s permissionScope) includes(addr permissionAddress) bool {
	return s.ns == addr.Namespace && (s.root == "" || addr.Name == s.root || strings.HasPrefix(addr.Name, s.root+"/"))
}

func observePermissionScopes(ctx context.Context, docs []document.File, addresses map[string]permissionAddress, scopes []permissionScope) bool {
	ops := 0

	for _, d := range docs {
		if ctx.Err() != nil {
			return false
		}

		p := d.Artifact().Metadata().Path

		addr, ok := addresses[p]
		if !ok || !permissionCode(d) {
			continue
		}

		for i := range scopes {
			ops++
			if ops > 500000 {
				return false
			}

			s := &scopes[i]
			if !s.includes(addr) {
				continue
			}

			observePermissions(d, &s.r)

			break
		}
	}

	return true
}

func declaredPermissionRecord(d document.File, isSkill, isPlugin bool) *permissionRecord {
	for _, u := range d.Units() {
		if isSkill && u.Origin != "frontmatter" || isPlugin && u.Origin != "file" {
			continue
		}

		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || tree.Root == nil {
			continue
		}

		at, e := u.View.Original(tree.Root.Span)
		if e != nil {
			continue
		}

		r := permissionRecord{span: at, declared: map[string]bool{}, observed: map[string]report.SourceRef{}}

		collectPermissionDeclarations(tree.Root, &r)

		return &r
	}

	return nil
}

func collectPermissionDeclarations(root *jsonconfig.Node, r *permissionRecord) {
	for _, key := range []string{"permissions", "allowed-tools"} {
		n := root.Get(key)
		if n == nil {
			continue
		}

		r.present = true

		for _, value := range configurationStrings(n) {
			for _, word := range permissionWords.FindAllString(strings.ToLower(value), 128) {
				r.wild = r.wild || wildcardPermissions[word]
				if category, ok := permissionCategories[word]; ok {
					r.declared[category] = true
				}
			}
		}
	}
}

func permissionCode(d document.File) bool {
	for _, u := range d.Units() {
		switch u.Language {
		case language.Go, language.Python, language.Shell, language.JavaScript, language.TypeScript, language.PowerShell, language.Ruby, language.PHP, language.Perl, language.Lua, language.Rust, language.C, language.CPP, language.Java:
			return true
		}
	}

	return false
}

func observePermissions(d document.File, r *permissionRecord) {
	r.code = true
	for _, c := range capPatterns {
		if _, ok := r.observed[c.name]; ok {
			continue
		}

		m := c.rx.FindStringIndex(d.Artifact().Content())
		if m == nil {
			continue
		}

		meta := d.Artifact().Metadata()
		r.observed[c.name] = report.SourceRef{
			Path:       meta.Path,
			SHA256:     meta.SHA256,
			ByteStart:  m[0],
			ByteEnd:    m[1],
			SpanSHA256: artifact.Hash([]byte(d.Artifact().Content()[m[0]:m[1]])),
		}
	}
}

// Supported configuration fields accept a scalar or a shallow array of string
// values. Nested objects do not silently become permission declarations.
func configurationStrings(n *jsonconfig.Node) []string {
	var values []string
	if value, ok := n.Text(); ok {
		values = append(values, value)
	}

	if n == nil {
		return values
	}

	for _, element := range n.Elements {
		if value, ok := element.Text(); ok {
			values = append(values, value)
		}
	}

	return values
}
