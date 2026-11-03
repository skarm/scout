package metadata

import (
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/mcpsnapshot"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func collectMCPSnapshot(d document.File, r *report.MetadataReport) (bool, bool) {
	candidate := strings.HasSuffix(strings.ToLower(d.Artifact().Metadata().Path), ".mcp-snapshot.json")
	for _, u := range d.Units() {
		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || u.Origin != "file" || u.Language != language.JSON {
			continue
		}

		schema, _ := tree.Root.Get("schema").Text()
		if !candidate && !strings.HasPrefix(schema, "scout.mcp-snapshot/") {
			continue
		}

		if !admitRecord(r) {
			return true, false
		}

		f := report.MetadataFile{
			Path: d.Artifact().Metadata().Path, Format: "mcp-snapshot", Status: "parsed_subset",
			Parser: u.ParserID, ParserVersion: u.ParserVersion, Fields: []report.MetadataField{}, Issues: []string{},
		}

		snapshot, err := mcpsnapshot.Inspect(tree.Root)
		if err != nil {
			f.Status = report.OutcomeUnsupported
			f.Issues = append(f.Issues, "mcp_snapshot_unverified")
		} else {
			identity := mcpField(d, u, "source", snapshot.Source, &f)

			f.MCP = &report.MCPSnapshotMetadata{
				Source:   mcpField(d, u, "snapshot", snapshot.Root, &f).Source,
				Identity: identity, Fields: mcpFields(d, u, snapshot.Initialize, "initialize.", &f,
					"protocolVersion", "serverInfo", "capabilities", "instructions"), Tools: []report.MCPToolMetadata{},
			}
			if extensions := mcpExtensions(snapshot.List, "tools"); len(extensions.Members) > 0 {
				f.MCP.Fields = append(f.MCP.Fields, mcpField(d, u, "tools.extensions", extensions, &f))
			}

			for _, tool := range snapshot.List.Get("tools").Elements {
				f.MCP.Tools = append(f.MCP.Tools, report.MCPToolMetadata{
					NameSHA256: artifact.Hash([]byte(tool.Get("name").String)),
					Source:     mcpField(d, u, "tool", tool, &f).Source,
					Fields:     mcpFields(d, u, tool, "", &f, "name", "title", "description", "inputSchema", "outputSchema", "annotations"),
				})
			}

			sort.Slice(f.MCP.Tools, func(i, j int) bool { return f.MCP.Tools[i].NameSHA256 < f.MCP.Tools[j].NameSHA256 })
		}

		if len(f.Issues) > 0 {
			r.Completeness = report.Partial
		}

		r.Files = append(r.Files, f)

		return true, true
	}

	if !candidate {
		return false, true
	}

	if !admitRecord(r) {
		return true, false
	}

	r.Completeness = report.Partial
	r.Files = append(r.Files, report.MetadataFile{
		Path: d.Artifact().Metadata().Path, Format: "mcp-snapshot",
		Status: report.OutcomeUnsupported, Fields: []report.MetadataField{}, Issues: []string{"mcp_snapshot_json_unavailable"},
	})

	return true, true
}

func mcpFields(d document.File, u document.Unit, node *jsonconfig.Node, prefix string, f *report.MetadataFile, names ...string) []report.MetadataField {
	fields := []report.MetadataField{}

	for _, name := range names {
		if value := node.Get(name); value != nil {
			fields = append(fields, mcpField(d, u, prefix+name, value, f))
		}
	}

	if extensions := mcpExtensions(node, names...); len(extensions.Members) > 0 {
		fields = append(fields, mcpField(d, u, prefix+"extensions", extensions, f))
	}

	return fields
}

func mcpExtensions(node *jsonconfig.Node, names ...string) *jsonconfig.Node {
	out := &jsonconfig.Node{Kind: jsonconfig.KindObject, Span: node.Span}
	for _, member := range node.Members {
		if !slices.Contains(names, member.Key) {
			out.Members = append(out.Members, member)
		}
	}

	return out
}

func mcpField(d document.File, u document.Unit, name string, n *jsonconfig.Node, f *report.MetadataFile) report.MetadataField {
	field := report.MetadataField{Name: name, Kind: n.Kind, ValueSHA256: canonicalHash(n)}

	span, err := u.View.Original(n.Span)
	if err != nil {
		f.Issues = append(f.Issues, "source_mapping_failed")
		return field
	}

	meta := d.Artifact().Metadata()
	field.Source = report.SourceRef{
		Path: meta.Path, SHA256: meta.SHA256, ByteStart: span.Start, ByteEnd: span.End,
		SpanSHA256: artifact.Hash([]byte(d.Artifact().Content()[span.Start:span.End])),
	}

	return field
}
