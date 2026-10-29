// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// SC10 concept adapted to supported parsed sources. No source is contacted.

package analyzer

import (
	"context"
	"net/url"
	"path"
	"strings"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/analysis/sourcepolicy"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"

	"github.com/skarm/scout/report"
)

type sourceRedirection struct{ declarations map[string]*check.Facts }

func (sourceRedirection) Rule() report.Rule {
	return report.Rule{
		ID:          ruleNVSC10,
		Version:     "4",
		Title:       "Dependency source added, redirected or unresolved",
		Description: "A supported declaration references a nondefault package source, local path or source override.",
		Severity:    report.Medium,
		Category:    "supply-chain",
		Method:      "structured-package-source",
		Limitation:  "Selected npm/PyPI JSON/TOML/requirements/npmrc and parsed shell registry/env declarations, including cargo index environment keys; selected Yarn, pip INI, Cargo, Maven and NuGet configurations. Alternate sources may be legitimate. No repository is contacted, no package manager is run and credentials are not copied into reports.",
	}
}

func (sourceRedirection) AppliesTo(document.File) bool { return true }
func (a sourceRedirection) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	out := Result{}
	collected := collectMatches(&out, budget)
	emit := func(at source.Span) { collected.span(at.Start, at.End) }

	if a.declarations != nil {
		cached, err := a.declarations[f.Artifact().Metadata().Path].Result(budget)
		for _, m := range cached.Matches {
			emit(source.Span{Start: m.Start, End: m.End})
		}

		out.Truncated = cached.Truncated
		if err != nil {
			return out, err
		}
	} else {
		out.Truncated = shell.SourceDeclarations(ctx, f, emit, nil)
	}

	out.Truncated = derivedSourceDeclarations(ctx, f, emit) || out.Truncated

	name := strings.ToLower(path.Base(f.Artifact().Metadata().Path))
	if unescaped, e := url.PathUnescape(name); e == nil {
		name = strings.ToLower(path.Base(unescaped))
	}

	out.Truncated = directSourceConfig(ctx, name, f.Artifact().Content(), emit) || out.Truncated
	if err := sourceTextDeclarations(ctx, name, f.Artifact().Content(), emit); err != nil {
		return out, err
	}

	inspectSourceUnits(ctx, f, name, emit)

	return out, ctx.Err()
}

func derivedSourceDeclarations(ctx context.Context, f document.File, emit func(source.Span)) bool {
	derived, gap := f.DerivedConfigs()
	limited := gap

	for _, config := range derived {
		if config.File == nil {
			limited = true
			continue
		}

		result, err := (sourceRedirection{}).Find(ctx, *config.File, 1)
		if len(result.Matches) > 0 {
			emit(config.Span)
		}

		limited = limited || result.Truncated || err != nil
	}

	return limited
}

func inspectSourceUnits(ctx context.Context, f document.File, name string, emit func(source.Span)) {
	for _, u := range f.Units() {
		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || tree.Root == nil {
			continue
		}

		mark := func(n *jsonconfig.Node) {
			if n != nil {
				if at, err := u.View.Original(n.Span); err == nil {
					emit(at)
				}
			}
		}
		inspectSourceTree(ctx, name, f.Artifact().Metadata().Path, tree.Root, mark)
	}
}

func sourceTextDeclarations(ctx context.Context, name, text string, emit func(source.Span)) error {
	classify := npmrcSourceLine

	switch {
	case name == ".npmrc":
	case name == "requirements.txt" || strings.HasPrefix(name, "requirements-"):
		classify = requirementsSourceFlag
	default:
		return nil
	}

	offset := 0

	for line := range strings.Lines(text) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		trim := strings.TrimSpace(line)
		if !sourceConfigComment(trim) && classify(trim) {
			emit(source.Span{Start: offset, End: offset + len(line)})
		}

		offset += len(line)
	}

	return nil
}

func npmrcSourceLine(text string) bool {
	key, value, assigned := strings.Cut(text, "=")
	key = strings.TrimSpace(key)

	return assigned && (key == "registry" || strings.HasSuffix(key, ":registry")) && !sourcepolicy.Default(strings.TrimSpace(value), report.EcosystemNPM)
}

func inspectSourceTree(ctx context.Context, name, filePath string, root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	switch name {
	case ".yarnrc.yml", ".yarnrc.yaml":
		checkYarnSources(ctx, root, 0, mark)
	case "config.toml":
		if strings.Contains(strings.ToLower(filePath), ".cargo/") {
			checkCargoSources(root, mark)
		}
	case "package.json":
		checkPackageSources(root, mark)
	case "package-lock.json", "npm-shrinkwrap.json":
		checkResolvedSources(ctx, root, 0, mark)
	case "pyproject.toml":
		checkPyprojectSources(root, mark)
	case "pipfile", "pipfile.lock":
		checkPipfileSources(root, mark)
	case "uv.lock", "poetry.lock":
		checkPythonLockSources(root, mark)
	}
}

func checkYarnSources(ctx context.Context, n *jsonconfig.Node, depth int, mark func(*jsonconfig.Node)) {
	if n == nil || depth > 32 || ctx.Err() != nil {
		return
	}

	for _, m := range n.Members {
		if m.Key == "npmRegistryServer" {
			if v, ok := m.Value.Text(); !ok || !sourcepolicy.Default(v, report.EcosystemNPM) {
				mark(m.Value)
			}
		}

		checkYarnSources(ctx, m.Value, depth+1, mark)
	}
}

func checkCargoSources(root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	for _, member := range root.GetOrEmpty("source").Members {
		for _, key := range []string{"replace-with", "registry", "git", "directory", "local-registry"} {
			node := member.Value.Get(key)
			if node == nil {
				continue
			}

			if key != "registry" || !defaultCargoSource(node) {
				mark(node)
			}
		}
	}

	for _, member := range root.GetOrEmpty("registries").Members {
		if node := member.Value.Get("index"); node != nil && !defaultCargoSource(node) {
			mark(node)
		}
	}
}

func defaultCargoSource(node *jsonconfig.Node) bool {
	value, known := node.Text()
	return known && sourcepolicy.ShellDefault(value, "cargo")
}

func checkPackageSources(root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"} {
		n := root.Get(field)
		if n == nil {
			continue
		}

		for _, m := range n.Members {
			v, ok := m.Value.Text()
			if ok && (strings.HasPrefix(v, "npm:") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "git") || strings.HasPrefix(v, "http") || strings.HasPrefix(v, "link:")) {
				mark(m.Value)
			}
		}
	}
}

func checkResolvedSources(ctx context.Context, n *jsonconfig.Node, depth int, mark func(*jsonconfig.Node)) {
	if n == nil || depth > 32 || ctx.Err() != nil {
		return
	}

	if v, ok := n.Get("resolved").Text(); ok && !sourcepolicy.Default(v, report.EcosystemNPM) {
		mark(n.Get("resolved"))
	}

	for _, m := range n.Members {
		checkResolvedSources(ctx, m.Value, depth+1, mark)
	}

	for _, v := range n.Elements {
		checkResolvedSources(ctx, v, depth+1, mark)
	}
}

func checkPyprojectSources(root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	for _, n := range []*jsonconfig.Node{root.Get("tool").Get("poetry").Get("source"), root.Get("tool").Get("uv").Get("index")} {
		if n == nil {
			continue
		}

		items := n.Elements
		if n.Kind == jsonconfig.KindObject {
			items = []*jsonconfig.Node{n}
		}

		for _, item := range items {
			address := item.Get("url")
			if value, ok := address.Text(); address != nil && (!ok || !sourcepolicy.Default(value, report.EcosystemPyPI)) {
				mark(address)
			}
		}
	}

	if n := root.Get("tool").Get("uv").Get("sources"); n != nil {
		mark(n)
	}
}

func checkPipfileSources(root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	n := root.Get("source")
	if n == nil {
		n = root.Get("_meta").Get("sources")
	}

	if n != nil {
		for _, v := range n.Elements {
			if s, ok := v.Get("url").Text(); ok && !sourcepolicy.Default(s, report.EcosystemPyPI) {
				mark(v)
			}
		}
	}
}

func checkPythonLockSources(root *jsonconfig.Node, mark func(*jsonconfig.Node)) {
	n := root.Get("package")
	if n != nil {
		for _, p := range n.Elements {
			src := p.Get("source")
			if src == nil {
				continue
			}

			v, ok := src.Get("registry").Text()
			if !ok {
				v, ok = src.Get("url").Text()
			}

			if !ok || !sourcepolicy.Default(v, report.EcosystemPyPI) {
				mark(src)
			}
		}
	}
}
