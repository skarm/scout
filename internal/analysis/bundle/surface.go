package bundle

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/environment"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

const (
	maxSurfaceFactBytes = 1024
	maxSurfaceFacts     = 4096
)

var skillLink = regexp.MustCompile(`\[[^\]\r\n]*\]\(([^\s)]+)\)`)

// CollectSurface reuses the bundle observers on already prepared documents under
// a separate, explicitly reserved operation quota. It never reads the filesystem.
func CollectSurface(ctx context.Context, docs []document.File, extraction report.ExtractionReport, operations uint64, includeCapabilityDetails bool) environment.Surface {
	surface := environment.Surface{Facts: []environment.SurfaceFact{}, IncludeCapabilityDetails: includeCapabilityDetails}
	if operations == 0 || ctx.Err() != nil {
		return surface
	}

	bind(analysisbudget.WithLimit(ctx, operations), nil, docs, extraction, 0, &surface)

	for _, d := range docs {
		name := d.Artifact().Metadata().Path
		if !strings.HasPrefix(name, report.ObjectPathPrefix) && (strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".toml")) && !surfaceParsedConfig(d) {
			surface.Complete = false
		}
	}

	return surface
}

func surfaceParsedConfig(d document.File) bool {
	for _, unit := range d.Units() {
		if tree, ok := unit.Tree.(parse.JSONTree); ok && tree.Root != nil {
			return true
		}
	}

	return false
}

func (b *bundleAnalysis) surfaceFact(kind, value, file string, ref report.SourceRef) {
	if b.surface == nil || ref.Path == "" || ref.ByteEnd <= ref.ByteStart {
		return
	}

	if b.surface.IncludeCapabilityDetails && !report.IsComparedCapability(kind) {
		return
	}

	addr, ok := b.addresses[file]
	if !ok || addr.Namespace != artifact.RootNamespace {
		b.surface.Limited = true
		return
	}

	if len(value) > maxSurfaceFactBytes {
		b.surface.Limited = true
		return
	}

	fact := environment.SurfaceFact{Kind: kind, Value: value, Source: ref}
	if b.surface.IncludeCapabilityDetails {
		line, _, err := b.docs[file].Index().Position(ref.ByteStart)
		if err != nil {
			b.surface.Limited = true
			return
		}

		fact.Line = line
	} else if skill := b.scope(file); skill != nil {
		fact.Scope = skill.file
	} else {
		fact.Scope = file
	}

	if _, seen := b.surfaceSeen[fact]; seen {
		return
	}

	if len(b.surface.Facts) >= maxSurfaceFacts {
		b.surface.Limited = true
		return
	}

	if b.surfaceSeen == nil {
		b.surfaceSeen = map[environment.SurfaceFact]struct{}{}
	}

	b.surfaceSeen[fact] = struct{}{}
	b.surface.Facts = append(b.surface.Facts, fact)
}

func (b *bundleAnalysis) observeServerNames(d document.File, u document.Unit, n *jsonconfig.Node) {
	if b.surface == nil {
		return
	}

	for _, field := range []string{"mcpServers", "mcp_servers"} {
		servers := n.Get(field)
		if servers == nil {
			continue
		}

		if servers.Kind != jsonconfig.KindObject {
			b.surface.Limited = true
			continue
		}

		for _, member := range servers.Members {
			if !b.step() {
				return
			}

			if member.Value.Kind != jsonconfig.KindObject {
				b.surface.Limited = true
				continue
			}

			ref := b.unitRef(d, u, member.KeySpan)
			b.surfaceFact("mcp_identifier", member.Key, ref.Path, ref)
		}
	}
}

func (b *bundleAnalysis) observeSurfaceTools(d document.File, u document.Unit, tools *jsonconfig.Node) {
	if b.surface == nil || tools == nil {
		return
	}

	if tools.Kind != jsonconfig.KindArray {
		b.surface.Limited = true
		return
	}

	for _, tool := range tools.Elements {
		if !b.step() {
			return
		}

		node := tool.Get("name")

		name, ok := node.Text()
		if !ok || name == "" {
			b.surface.Limited = true
			continue
		}

		ref := b.unitRef(d, u, node.Span)
		b.surfaceFact("tool_identifier", name, ref.Path, ref)
	}
}

func (b *bundleAnalysis) surfaceSkills(docs []document.File) {
	var skills map[document.Address]string

	if !b.surface.IncludeCapabilityDetails {
		skills = make(map[document.Address]string, len(b.scopes))
		for _, scope := range b.scopes {
			skills[b.addresses[scope.file]] = scope.file
		}
	}

	for _, d := range docs {
		name := d.Artifact().Metadata().Path

		addr, ok := b.addresses[name]
		if !ok || !strings.EqualFold(path.Base(addr.Name), artifact.SkillManifest) || !b.step() {
			continue
		}

		text := d.Artifact().Content()
		if len(text) == 0 || d.Artifact().Metadata().Kind != report.FileKindText {
			b.surface.Limited = true
			continue
		}

		if !b.surface.IncludeCapabilityDetails {
			b.surfaceFact("skill", "", name, b.reference(name, 0, len(text)))
		}

		if addr.Namespace == artifact.RootNamespace {
			b.observeSkillFrontmatter(d, name)
		}

		if b.surface.IncludeCapabilityDetails {
			continue
		}

		b.surfaceSkillLinks(text, name, addr, skills)
	}
}

func (b *bundleAnalysis) surfaceSkillLinks(text, name string, addr document.Address, skills map[document.Address]string) {
	links := skillLink.FindAllStringSubmatchIndex(text, maxSurfaceFacts+1)
	if len(links) > maxSurfaceFacts {
		b.surface.Limited = true
	}

	for _, link := range links {
		if !b.step() {
			return
		}

		value, _, _ := strings.Cut(text[link[2]:link[3]], "#")
		if value == "" || strings.ContainsAny(value, ":\\?%") || path.IsAbs(value) {
			continue
		}

		target := path.Clean(path.Join(path.Dir(addr.Name), value))
		if target == ".." || strings.HasPrefix(target, "../") {
			continue
		}

		if file := skills[document.Address{Namespace: addr.Namespace, Name: target}]; file != "" && file != name {
			b.surfaceFact("skill_reference", file, name, b.reference(name, link[0], link[1]))
		}
	}
}

func (b *bundleAnalysis) observeSkillFrontmatter(d document.File, name string) {
	for _, unit := range d.Units() {
		if unit.Origin != "frontmatter" {
			continue
		}

		tree, ok := unit.Tree.(parse.JSONTree)
		if !ok || tree.Root == nil || tree.Root.Kind != jsonconfig.KindObject {
			break
		}

		if b.surface.IncludeCapabilityDetails {
			b.observeSkillPermissions(d, unit, tree.Root)
			return
		}

		node := tree.Root.Get("description")
		value, ok := node.Text()

		if !ok || strings.TrimSpace(value) == "" {
			return
		}

		if len(value) <= maxSurfaceFactBytes {
			b.surfaceFact(report.EnvironmentSkillDescription, value, name, b.unitRef(d, unit, node.Span))
		} else {
			b.surface.UnknownSkillDescriptions++
		}

		return
	}

	if b.surface.IncludeCapabilityDetails {
		return
	}

	for _, region := range d.Regions() {
		if region.Kind == "frontmatter" {
			b.surface.UnknownSkillDescriptions++
			return
		}
	}
}

func (b *bundleAnalysis) observeSkillPermissions(d document.File, unit document.Unit, root *jsonconfig.Node) {
	for _, field := range []string{"allowed-tools", "permissions"} {
		node := root.Get(field)
		if node == nil {
			continue
		}

		if node.Kind == jsonconfig.KindString {
			b.observeSkillPermission(d, unit, field, node)
			continue
		}

		if node.Kind != jsonconfig.KindArray {
			b.surface.Limited = true
			continue
		}

		for _, item := range node.Elements {
			b.observeSkillPermission(d, unit, field, item)
		}
	}
}

func (b *bundleAnalysis) observeSkillPermission(d document.File, unit document.Unit, field string, node *jsonconfig.Node) {
	if !b.step() {
		return
	}

	value, ok := node.Text()
	if !ok {
		b.surface.Limited = true
		return
	}

	if value = strings.TrimSpace(value); value != "" {
		ref := b.unitRef(d, unit, node.Span)
		b.surfaceFact(field, artifact.Hash([]byte(value)), ref.Path, ref)
	}
}
