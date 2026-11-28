// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified TP4 planner: scanner-issued excerpts, nearest package scope,
// independent verification and explicit omissions replace free-form model text.

package semantic

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

var descriptionField = regexp.MustCompile(`(?m)^[\t ]*description[\t ]*:[\t ]*\S`)

type (
	toolAddress struct{ namespace, name string }
	toolScope   struct {
		file      artifact.File
		address   toolAddress
		root      string
		described bool
	}
	toolScopeKey   struct{ namespace, root string }
	toolScopeIndex map[toolScopeKey]*toolScope
)

func (p *planner) planToolConsistency() {
	addresses := p.toolAddresses()

	scopes, ok := p.toolScopes(addresses)
	if !ok {
		return
	}

	index := indexToolScopes(scopes)

	names := make([]string, 0, len(addresses))
	for name := range addresses {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if p.ctx.Err() != nil {
			p.gap("tool_consistency_planning_cancelled", name, 0, 0, "", "")
			return
		}

		p.planCodeConsistency(name, addresses[name], index)
	}
}

func (p *planner) toolScopes(addresses map[string]toolAddress) ([]toolScope, bool) {
	scopes := make([]toolScope, 0)

	for name, addr := range addresses {
		if p.ctx.Err() != nil {
			p.gap("tool_consistency_planning_cancelled", name, 0, 0, "", "")
			return nil, false
		}

		f := p.files[name]
		base := path.Base(addr.name)
		isSkill := strings.EqualFold(base, artifact.SkillManifest)

		root, isPlugin := artifact.PluginManifestRoot(addr.name)
		if !isSkill && !isPlugin {
			continue
		}

		if !isPlugin {
			root = path.Dir(addr.name)
		}

		// Ownership is independent of eligibility: an inner package with no
		// description must not inherit an outer package's asserted purpose.
		scopes = append(scopes, toolScope{
			file:      f,
			address:   addr,
			root:      root,
			described: p.toolDescriptionDeclared(f, isSkill),
		})
	}

	return scopes, true
}

func preparedDescriptions(docs []document.File) map[string]bool {
	descriptions := make(map[string]bool)

	for _, doc := range docs {
		for _, unit := range doc.Units() {
			if unit.Origin != "frontmatter" {
				continue
			}

			name := doc.Artifact().Metadata().Path
			descriptions[name] = false

			if tree, ok := unit.Tree.(parse.JSONTree); ok && tree.Root != nil && tree.Root.Kind == jsonconfig.KindObject {
				text, valid := tree.Root.Get("description").Text()
				descriptions[name] = valid && strings.TrimSpace(text) != ""
			}
		}
	}

	return descriptions
}

func (p *planner) toolDescriptionDeclared(file artifact.File, isSkill bool) bool {
	text := file.Content()
	if isSkill {
		if described, prepared := p.descriptions[file.Metadata().Path]; prepared {
			return described
		}
		// Without a selected YAML parser (or prepared documents in standalone
		// Run), retain the bounded lexical subset; this is not YAML semantics.
		trim := strings.TrimPrefix(text, "\ufeff")
		if strings.HasPrefix(trim, "---\n") || strings.HasPrefix(trim, "---\r\n") {
			body := trim[strings.IndexByte(trim, '\n')+1:]
			at := 0

			for line := range strings.SplitAfterSeq(body, "\n") {
				delimiter := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
				if delimiter == "---" || delimiter == "..." {
					return descriptionField.MatchString(body[:at])
				}

				at += len(line)
			}
		}

		return false
	}

	if node, err := jsonconfig.Parse(p.ctx, text); err == nil {
		description, ok := node.Get("description").Text()
		return ok && strings.TrimSpace(description) != ""
	}

	return false
}

func (p *planner) planCodeConsistency(name string, addr toolAddress, scopes toolScopeIndex) {
	f := p.files[name]
	if f.Metadata().Kind != report.FileKindText || contentKind(name, f.Content()) != "code" {
		return
	}

	scope := containingToolScope(addr, scopes)

	if scope == nil || !scope.described {
		return
	}

	decl := scope.file
	if len(decl.Content()) > p.options.ChunkBytes/2 {
		p.gap("tool_consistency_declaration_limit", name, 0, len(f.Content()), "", "")
		return
	}

	if len(f.Content()) == 0 {
		return
	}

	chunk := p.options.ChunkBytes - len(decl.Content())
	for start := 0; start < len(f.Content()); {
		if p.ctx.Err() != nil {
			p.gap("tool_consistency_planning_cancelled", name, start, len(f.Content()), "", "")
			break
		}

		end := boundary(f.Content(), start, min(len(f.Content()), start+chunk))
		req := p.codeConsistencyRequest(decl, f, start, end)

		if reason := p.add(req); reason != "" {
			p.gap("tool_consistency_"+reason, name, start, len(f.Content()), "", "")
			break
		}

		start = end
	}
}

func (p *planner) codeConsistencyRequest(decl, f artifact.File, start, end int) review.Request {
	req := p.request(knowledge.ModeToolConsistency)
	req.ScopeID = artifact.Hash([]byte("TP4\x00" + decl.Metadata().Path))

	req.Excerpts = p.excerpts(decl, 0, len(decl.Content()))
	for i := range req.Excerpts {
		req.Excerpts[i].ContentKind = "tool_declaration"
	}

	code := p.excerpts(f, start, end)
	for i := range code {
		code[i].ContentKind = "code"
	}

	req.Excerpts = append(req.Excerpts, code...)

	req.Links = p.links(req.Excerpts)

	return req
}

func (p *planner) toolAddresses() map[string]toolAddress {
	addresses := map[string]toolAddress{}

	for name := range p.files {
		if !strings.HasPrefix(name, report.ObjectPathPrefix) {
			addresses[name] = toolAddress{namespace: artifact.RootNamespace, name: name}
		}
	}

	for _, o := range p.extraction.Objects {
		if o.Role == report.DerivedRoleArchiveMember && (o.ExtractorID == report.ExtractorZIP32 || o.ExtractorID == report.ExtractorTar) {
			addresses[o.File.Path] = toolAddress{namespace: artifact.ArchiveNamespace(o.ParentPath), name: o.MemberName}
		}
	}

	return addresses
}

func toolConsistencyEvidence(citations []review.Citation, excerpts []review.Excerpt) bool {
	seen := map[string]bool{}
	for _, c := range citations {
		seen[c.ExcerptID] = true
	}

	declaration, code := false, false

	for _, ex := range excerpts {
		if !seen[ex.ID] {
			continue
		}

		if ex.ContentKind == "tool_declaration" {
			declaration = true
		}

		if ex.ContentKind == "code" {
			code = true
		}
	}

	return declaration && code
}

func indexToolScopes(scopes []toolScope) toolScopeIndex {
	index := toolScopeIndex{}

	for i := range scopes {
		candidate := &scopes[i]

		key := toolScopeKey{namespace: candidate.address.namespace, root: candidate.root}
		if previous := index[key]; previous != nil {
			if previous.described && !candidate.described {
				continue
			}

			if previous.described == candidate.described && previous.file.Metadata().Path < candidate.file.Metadata().Path {
				continue
			}
		}

		index[key] = candidate
	}

	return index
}

// Admitted captured paths have bounded depth. Looking up their ancestors avoids
// comparing every code file with every unrelated package declaration.
func containingToolScope(addr toolAddress, index toolScopeIndex) *toolScope {
	for root := path.Dir(addr.name); ; root = path.Dir(root) {
		if scope := index[toolScopeKey{namespace: addr.namespace, root: root}]; scope != nil {
			return scope
		}

		if root == "." || root == "/" {
			return nil
		}
	}
}
