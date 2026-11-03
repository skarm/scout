// Package mcpsnapshot validates passive, operator-imported MCP declarations.
// It never connects to servers, executes tools or resolves schema references.
package mcpsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	Schema   = "scout.mcp-snapshot/v1"
	MaxTools = 256
)

// Document retains nodes in one bounded parsed snapshot, with original spans.
type Document struct {
	Root, Source, Initialize, List *jsonconfig.Node
}

// Create wraps an imported {initialize: InitializeResult, tools: ListToolsResult}
// capture. Source is an operator-chosen identity, not serverInfo.name or a URL
// that Scout will contact. The returned document contains the captured values.
func Create(ctx context.Context, source string, capture []byte) (json.RawMessage, error) {
	root, err := jsonconfig.Parse(ctx, string(capture))
	if err != nil {
		return nil, err
	}

	if source == "" || len(source) > 1024 || !utf8.ValidString(source) || !onlyFields(root, "initialize", "tools") {
		return nil, errors.New("invalid MCP capture or source identity")
	}

	if err := validateCapture(root); err != nil {
		return nil, err
	}

	initialize, tools := root.Get("initialize"), root.Get("tools")

	out, err := json.Marshal(struct {
		Schema     string          `json:"schema"`
		Source     string          `json:"source"`
		Initialize json.RawMessage `json:"initialize"`
		Tools      json.RawMessage `json:"tools"`
	}{Schema, source, capture[initialize.Span.Start:initialize.Span.End], capture[tools.Span.Start:tools.Span.End]})
	if err != nil {
		return nil, errors.New("cannot encode MCP snapshot")
	}

	// Operator JSON publication appends one newline within the parser ceiling.
	if len(out) >= jsonconfig.MaxBytes {
		return nil, errors.New("MCP snapshot byte limit")
	}

	if _, err := jsonconfig.Parse(ctx, string(out)); err != nil {
		return nil, err
	}

	return out, nil
}

// Inspect checks the snapshot envelope and selected protocol shapes. Unknown
// protocol extension fields remain available for hashing; envelope fields are exact.
// This is not JSON Schema validation, authentication or a runtime completeness proof.
func Inspect(root *jsonconfig.Node) (Document, error) {
	d := Document{Root: root, Source: root.Get("source"), Initialize: root.Get("initialize"), List: root.Get("tools")}
	if !onlyFields(root, "schema", "source", "initialize", "tools") ||
		!stringValue(root.Get("schema"), Schema) || !nonemptyString(d.Source) || len(d.Source.String) > 1024 {
		return d, errors.New("invalid MCP snapshot envelope")
	}

	return d, validateCapture(root)
}

func validateCapture(root *jsonconfig.Node) error {
	initialize, list := root.Get("initialize"), root.Get("tools")
	if initialize == nil || initialize.Kind != jsonconfig.KindObject || list == nil || list.Kind != jsonconfig.KindObject {
		return errors.New("MCP capture requires initialize and tools results")
	}

	info := initialize.Get("serverInfo")
	if info == nil || info.Kind != jsonconfig.KindObject || !requiredKind(info, "name", jsonconfig.KindString) ||
		!requiredKind(info, "version", jsonconfig.KindString) || !nonemptyString(initialize.Get("protocolVersion")) ||
		!optionalKind(initialize, "instructions", jsonconfig.KindString) ||
		!requiredKind(initialize, "capabilities", jsonconfig.KindObject) {
		return errors.New("invalid MCP initialize result")
	}

	tools := list.Get("tools")
	if tools == nil || tools.Kind != jsonconfig.KindArray || len(tools.Elements) > MaxTools || list.Get("nextCursor") != nil ||
		list.Get("resultType") != nil && !stringValue(list.Get("resultType"), "complete") {
		return errors.New("MCP tools list is invalid, paginated or exceeds the tool limit")
	}

	names := map[string]bool{}
	for _, tool := range tools.Elements {
		if !validTool(tool) || names[tool.Get("name").String] {
			return errors.New("invalid or duplicate MCP tool declaration")
		}

		names[tool.Get("name").String] = true
	}

	return nil
}

func validTool(tool *jsonconfig.Node) bool {
	return tool != nil && tool.Kind == jsonconfig.KindObject && nonemptyString(tool.Get("name")) &&
		requiredKind(tool, "inputSchema", jsonconfig.KindObject) &&
		optionalKind(tool, "title", jsonconfig.KindString) && optionalKind(tool, "description", jsonconfig.KindString) &&
		optionalKind(tool, "outputSchema", jsonconfig.KindObject) && optionalKind(tool, "annotations", jsonconfig.KindObject)
}

func onlyFields(n *jsonconfig.Node, fields ...string) bool {
	if n == nil || n.Kind != jsonconfig.KindObject {
		return false
	}

	for _, field := range n.Members {
		if !slices.Contains(fields, field.Key) {
			return false
		}
	}

	return true
}

func nonemptyString(n *jsonconfig.Node) bool {
	return n != nil && n.Kind == jsonconfig.KindString && n.String != ""
}

func stringValue(n *jsonconfig.Node, value string) bool {
	return n != nil && n.Kind == jsonconfig.KindString && n.String == value
}

func requiredKind(n *jsonconfig.Node, field, kind string) bool {
	v := n.Get(field)
	return v != nil && v.Kind == kind
}

func optionalKind(n *jsonconfig.Node, field, kind string) bool {
	v := n.Get(field)
	return v == nil || v.Kind == kind
}
