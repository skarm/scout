package bundle

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

// Surface retains source-bound observations for an explicitly selected environment.
// It contains no source bodies and is never shared between independent scans.
type Surface struct {
	Complete bool
	Limited  bool
	Facts    []SurfaceFact
}

// SurfaceFact is a syntactic observation, not an assertion of activation or flow.
type SurfaceFact struct {
	Kind, Value, Scope string
	Source             report.SourceRef
}

const maxSurfaceFacts = 4096

var skillLink = regexp.MustCompile(`\[[^\]\r\n]*\]\(([^\s)]+)\)`)

// CollectSurface reuses the bundle observers on already prepared documents under
// a separate, explicitly reserved operation quota. It never reads the filesystem.
func CollectSurface(ctx context.Context, docs []document.File, extraction report.ExtractionReport, operations uint64) Surface {
	surface := Surface{Facts: []SurfaceFact{}}
	if operations == 0 || ctx.Err() != nil {
		return surface
	}

	bind(analysisbudget.WithLimit(ctx, operations), nil, docs, extraction, 0, &surface)

	for _, d := range docs {
		name := d.Artifact().Metadata().Path
		if !strings.HasPrefix(name, "scout-object://") && (strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".toml")) && !surfaceParsedConfig(d) {
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

	addr, ok := b.addresses[file]
	if !ok || addr.Namespace != "snapshot" {
		b.surface.Limited = true
		return
	}

	if len(value) > 1024 {
		b.surface.Limited = true
		return
	}

	scope := file
	if skill := b.scope(file); skill != nil {
		scope = skill.file
	}

	fact := SurfaceFact{Kind: kind, Value: value, Scope: scope, Source: ref}
	if b.surfaceSeen[fact] {
		return
	}

	if len(b.surface.Facts) >= maxSurfaceFacts {
		b.surface.Limited = true
		return
	}

	if b.surfaceSeen == nil {
		b.surfaceSeen = map[SurfaceFact]bool{}
	}

	b.surfaceSeen[fact] = true
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
	skills := map[document.Address]string{}
	for _, scope := range b.scopes {
		skills[b.addresses[scope.file]] = scope.file
	}

	for _, d := range docs {
		name := d.Artifact().Metadata().Path

		addr, ok := b.addresses[name]
		if !ok || !strings.EqualFold(path.Base(addr.Name), "SKILL.md") || !b.step() {
			continue
		}

		text := d.Artifact().Content()
		if len(text) == 0 || d.Artifact().Metadata().Kind != "text" {
			b.surface.Limited = true
			continue
		}

		b.surfaceFact("skill", "", name, b.reference(name, 0, len(text)))

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
}
