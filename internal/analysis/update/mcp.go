package update

import "github.com/skarm/scout/report"

func (b *builder) mcpSnapshots() {
	if b.before.Metadata.Completeness != report.Complete || b.after.Metadata.Completeness != report.Complete {
		// A truncated inventory may omit every MCP record, including on both
		// sides. Empty retained declarations cannot establish equality.
		b.issue("mcp_metadata_inventory_incomplete")
	}

	old, next := b.mcpIndex(b.before, b.old), b.mcpIndex(b.after, b.next)
	for _, id := range sortedKeys(old, next) {
		if !b.step() {
			return
		}

		a, z := old[id], next[id]
		if !b.mcpSidesAvailable(id, a, z) {
			continue
		}

		if a == nil || z == nil {
			change := "added"
			if z == nil {
				change = "removed"
			}

			b.recordMCP(id, "", "snapshot", change, mcpSource(a), mcpSource(z))

			continue
		}

		if a.MCP.Identity.ValueSHA256 != z.MCP.Identity.ValueSHA256 {
			b.issue("mcp_source_identity_mismatch")
			b.recordMCP(id, "", "source", "unverified", &a.MCP.Identity.Source, &z.MCP.Identity.Source)

			continue
		}

		b.mcpFields(id, "", a.MCP.Fields, z.MCP.Fields)
		b.mcpTools(id, a.MCP.Tools, z.MCP.Tools)
	}
}

func (b *builder) mcpIndex(r report.Analysis, inventory inventory) map[string]*report.MetadataFile {
	out := map[string]*report.MetadataFile{}

	for i := range r.Metadata.Files {
		if !b.step() {
			break
		}

		f := &r.Metadata.Files[i]
		if f.Format != "mcp-snapshot" {
			continue
		}

		o := inventory.byPath[f.Path]
		if o == nil {
			b.issue("mcp_snapshot_object_unavailable")
			continue
		}

		if _, exists := out[o.key]; exists {
			b.issue("ambiguous_mcp_snapshot")

			out[o.key] = nil

			continue
		}

		out[o.key] = f
	}

	return out
}

func (b *builder) mcpSidesAvailable(id string, a, z *report.MetadataFile) bool {
	valid := true

	for _, side := range []struct {
		f *report.MetadataFile
		i inventory
	}{{a, b.old}, {z, b.next}} {
		o := side.i.byKey[id]
		if side.f == nil && o == nil && side.i.complete {
			continue
		}

		if side.f == nil || o == nil || o.file.Status != report.CaptureCaptured ||
			side.f.Status != "parsed_subset" || len(side.f.Issues) > 0 || side.f.MCP == nil {
			valid = false
		}
	}

	if !valid {
		b.issue("mcp_snapshot_unverified")

		if mcpSource(a) != nil || mcpSource(z) != nil {
			b.recordMCP(id, "", "snapshot", "unverified", mcpSource(a), mcpSource(z))
		}
	}

	return valid
}

func mcpSource(f *report.MetadataFile) *report.SourceRef {
	if f == nil || f.MCP == nil || f.MCP.Source.ByteEnd <= f.MCP.Source.ByteStart {
		return nil
	}

	return &f.MCP.Source
}

func (b *builder) mcpTools(id string, before, after []report.MCPToolMetadata) {
	old, next := map[string]report.MCPToolMetadata{}, map[string]report.MCPToolMetadata{}
	for _, tool := range before {
		old[tool.NameSHA256] = tool
	}

	for _, tool := range after {
		next[tool.NameSHA256] = tool
	}

	for _, name := range sortedKeys(old, next) {
		if !b.step() {
			return
		}

		a, aok := old[name]

		z, zok := next[name]
		switch {
		case !aok:
			b.recordMCP(id, name, "tool", "added", nil, &z.Source)
		case !zok:
			b.recordMCP(id, name, "tool", "removed", &a.Source, nil)
		default:
			b.mcpFields(id, name, a.Fields, z.Fields)
		}
	}
}

func (b *builder) mcpFields(id, tool string, before, after []report.MetadataField) {
	old, next := map[string]report.MetadataField{}, map[string]report.MetadataField{}
	for _, field := range before {
		old[field.Name] = field
	}

	for _, field := range after {
		next[field.Name] = field
	}

	for _, name := range sortedKeys(old, next) {
		if !b.step() {
			return
		}

		a, aok := old[name]

		z, zok := next[name]
		switch {
		case !aok:
			b.recordMCP(id, tool, name, "added", nil, &z.Source)
		case !zok:
			b.recordMCP(id, tool, name, "removed", &a.Source, nil)
		case a.ValueSHA256 != z.ValueSHA256:
			b.recordMCP(id, tool, name, "modified", &a.Source, &z.Source)
		}
	}
}

func (b *builder) recordMCP(id, tool, field, change string, before, after *report.SourceRef) {
	if !b.retain() {
		return
	}

	if before != nil {
		ref := *before
		before = &ref
	}

	if after != nil {
		ref := *after
		after = &ref
	}

	b.delta.MCPChanges = append(b.delta.MCPChanges, report.MCPChange{
		ObjectID: id, ToolSHA256: tool, Field: field, Change: change, Before: before, After: after,
	})
	b.delta.Counts.MCPChanges++
}
