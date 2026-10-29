package metadata

import (
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

// Structured messages are untrusted declarations. Roles inside this envelope
// describe the artifact's protocol; they never become Scout system messages.
func collectStructured(d document.File, r *report.MetadataReport) (bool, bool) {
	candidate := strings.HasSuffix(strings.ToLower(d.Artifact().Metadata().Path), ".aisop.json")
	for _, u := range d.Units() {
		tree, ok := u.Tree.(parse.JSONTree)
		if !ok || u.Language != language.JSON {
			continue
		}

		protocol, payload, valid := structuredEnvelope(tree.Root)
		if !candidate && !valid {
			continue
		}

		if !admitRecord(r) {
			return true, false
		}

		f := report.MetadataFile{
			Path:          d.Artifact().Metadata().Path,
			Format:        "structured-agent",
			Status:        "parsed_subset",
			Parser:        u.ParserID,
			ParserVersion: u.ParserVersion,
			Fields:        []report.MetadataField{},
			Issues:        []string{},
		}
		if !valid {
			f.Status = report.OutcomeUnsupported
			f.Issues = append(f.Issues, "structured_envelope_unverified")
			r.Completeness = report.Partial
		} else {
			f.Format = strings.ToLower(strings.Fields(protocol.String)[0])
			addStructuredField(d, u, "protocol", protocol, &f)

			for _, key := range []string{"aisop", "aisp_contract"} {
				if body, ok := structuredField(payload, key); ok && body.Kind == jsonconfig.KindObject {
					collectStructuredFields(d, u, body, &f)
				}
			}

			collectStructuredFields(d, u, payload, &f)

			if len(f.Issues) > 0 {
				r.Completeness = report.Partial
			}
		}

		r.Files = append(r.Files, f)

		return true, true
	}

	if candidate {
		if !admitRecord(r) {
			return true, false
		}

		r.Completeness = report.Partial
		r.Files = append(r.Files, report.MetadataFile{
			Path:   d.Artifact().Metadata().Path,
			Format: "structured-agent",
			Status: report.OutcomeUnsupported,
			Fields: []report.MetadataField{},
			Issues: []string{"structured_json_unavailable"},
		})

		return true, true
	}

	return false, true
}

func structuredEnvelope(root *jsonconfig.Node) (*jsonconfig.Node, *jsonconfig.Node, bool) {
	if root == nil || root.Kind != jsonconfig.KindArray || len(root.Elements) != 2 {
		return nil, nil, false
	}

	system, user := root.Elements[0], root.Elements[1]
	if !nodeStringField(system, "role", "system") || !nodeStringField(user, "role", "user") {
		return nil, nil, false
	}

	systemBody, ok := structuredField(system, "content")
	if !ok || systemBody.Kind != jsonconfig.KindObject {
		return nil, nil, false
	}

	protocol, ok := structuredField(systemBody, "protocol")
	if !ok || protocol.Kind != jsonconfig.KindString || !(strings.HasPrefix(protocol.String, "AISOP V") || strings.HasPrefix(protocol.String, "AISP V")) {
		return nil, nil, false
	}

	body, ok := structuredField(user, "content")
	if !ok || body.Kind != jsonconfig.KindObject {
		return nil, nil, false
	}

	aisop, a := structuredField(body, "aisop")
	aisp, b := structuredField(body, "aisp_contract")

	return protocol, body, a && aisop.Kind == jsonconfig.KindObject || b && aisp.Kind == jsonconfig.KindObject
}

func nodeStringField(n *jsonconfig.Node, key, value string) bool {
	if n == nil {
		return false
	}

	f, ok := structuredField(n, key)

	return ok && f.Kind == jsonconfig.KindString && f.String == value
}

func collectStructuredFields(d document.File, u document.Unit, body *jsonconfig.Node, f *report.MetadataFile) {
	for _, item := range []struct{ key, name string }{{key: "declared_tools", name: "declared_tools"}, {
		key:  "tools",
		name: "tools",
	}, {
		key:  "functions",
		name: "workflow_nodes",
	}, {
		key:  "resources",
		name: "resource_anchors",
	}, {
		key:  "constraints",
		name: "constraint_anchors",
	}} {
		if node, ok := structuredField(body, item.key); ok {
			addStructuredField(d, u, item.name, node, f)
		}
	}
}

func addStructuredField(d document.File, u document.Unit, name string, n *jsonconfig.Node, f *report.MetadataFile) {
	at, err := u.View.Original(n.Span)
	if err != nil {
		f.Issues = append(f.Issues, "source_mapping_failed")
		return
	}

	meta := d.Artifact().Metadata()

	field := report.MetadataField{
		Name:        name,
		Kind:        n.Kind,
		ValueSHA256: canonicalHash(n),
		Source: report.SourceRef{
			Path:       meta.Path,
			SHA256:     meta.SHA256,
			ByteStart:  at.Start,
			ByteEnd:    at.End,
			SpanSHA256: artifact.Hash([]byte(d.Artifact().Content()[at.Start:at.End])),
		},
	}
	if name != "protocol" {
		field.ItemsComplete = n.Kind == jsonconfig.KindArray || n.Kind == jsonconfig.KindObject
		if !field.ItemsComplete {
			f.Issues = append(f.Issues, "structured_declaration_type_unverified")
		}

		for _, m := range n.Members {
			field.Items = append(field.Items, report.MetadataItem{
				NameSHA256:  artifact.Hash([]byte(m.Key)),
				ValueSHA256: canonicalHash(m.Value),
			})
		}

		for _, e := range n.Elements {
			field.Items = append(field.Items, report.MetadataItem{
				NameSHA256:  canonicalHash(e),
				ValueSHA256: canonicalHash(e),
			})
		}
	}

	f.Fields = append(f.Fields, field)
}

func structuredField(n *jsonconfig.Node, key string) (*jsonconfig.Node, bool) {
	node := n.Get(key)
	return node, node != nil
}
