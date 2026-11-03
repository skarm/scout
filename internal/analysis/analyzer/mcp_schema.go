package analyzer

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/source"
)

const maxSchemaURIBytes = 4096

type schemaReferenceScope struct {
	node *jsonconfig.Node
	base *url.URL
}

func inspectToolSchemaReferences(ctx context.Context, root *jsonconfig.Node, emit func(source.Span)) error {
	var problem error

	// Inspect both supported positions. An unrelated root.tools value must not
	// hide declarations in a JSON-RPC response's result.tools.
	for _, tools := range []*jsonconfig.Node{root.Get("tools"), root.Get("result").Get("tools")} {
		// Imported captures and scout.mcp-snapshot/v1 retain ListToolsResult.
		if tools != nil && tools.Kind == jsonconfig.KindObject {
			tools = tools.Get("tools")
		}

		if tools == nil || tools.Kind != jsonconfig.KindArray {
			continue
		}

		for _, tool := range tools.Elements {
			if err := ctx.Err(); err != nil {
				return errors.Join(problem, err)
			}

			for _, field := range []string{"inputSchema", "outputSchema"} {
				problem = errors.Join(problem, inspectSchemaReferences(ctx, tool.Get(field), emit))
			}
		}
	}

	return problem
}

func inspectSchemaReferences(ctx context.Context, root *jsonconfig.Node, emit func(source.Span)) error {
	var scopes []schemaReferenceScope

	resources := map[string]*jsonconfig.Node{}
	if err := collectSchemaScopes(ctx, root, &url.URL{}, true, resources, &scopes); err != nil {
		return err
	}

	var problem error

	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return errors.Join(problem, err)
		}

		for _, keyword := range []string{"$ref", "$dynamicRef"} {
			n := scope.node.Get(keyword)
			if n == nil {
				continue
			}

			ref, err := schemaURI(n)
			if err != nil {
				problem = errors.Join(problem, err)
				continue
			}

			resolved, err := resolveSchemaURI(scope.base, ref)
			if err != nil {
				problem = errors.Join(problem, err)
				continue
			}

			// Only the initial resource is classified for $dynamicRef. The
			// instance-dependent dynamic scope is never evaluated here.
			if resources[schemaResourceURI(resolved)] == nil {
				emit(n.Span)
			}
		}
	}

	return problem
}

// Only schema-bearing keywords are traversed: examples, defaults, const, enum
// and arbitrary extension data must not introduce references or local resources.
// The parsed JSON tree already enforces byte, node and depth limits.
func collectSchemaScopes(ctx context.Context, n *jsonconfig.Node, base *url.URL, resource bool, resources map[string]*jsonconfig.Node, scopes *[]schemaReferenceScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if n == nil || n.Kind == jsonconfig.KindBool {
		return nil
	}

	if n.Kind != jsonconfig.KindObject {
		return errors.New("MCP schema node shape is unsupported")
	}

	if dialect := n.Get("$schema"); dialect != nil {
		text, ok := dialect.Text()
		if !ok || strings.TrimSuffix(text, "#") != "https://json-schema.org/draft/2020-12/schema" {
			return errors.New("MCP schema reference dialect is unsupported")
		}
	}

	if id := n.Get("$id"); id != nil {
		u, err := schemaURI(id)
		if err != nil || u.Fragment != "" {
			return errors.New("MCP schema resource identity is unsupported")
		}
		// Imported tool schemas have no trusted retrieval URI. Inventing a
		// filesystem root would incorrectly alias foo and ../foo as local IDs.
		if !base.IsAbs() && !u.IsAbs() {
			return errors.New("MCP schema relative resource identity has no known base")
		}

		base, err = resolveSchemaURI(base, u)
		if err != nil {
			return err
		}

		resource = true
	}

	if resource {
		key := schemaResourceURI(base)
		if resources[key] != nil {
			return errors.New("MCP schema resource identity is ambiguous")
		}

		resources[key] = n
	}

	*scopes = append(*scopes, schemaReferenceScope{node: n, base: base})

	for _, member := range n.Members {
		if err := collectSchemaChildren(ctx, member, base, resources, scopes); err != nil {
			return err
		}
	}

	return nil
}

func collectSchemaChildren(ctx context.Context, member jsonconfig.Member, base *url.URL, resources map[string]*jsonconfig.Node, scopes *[]schemaReferenceScope) error {
	n := member.Value
	switch member.Key {
	case "$defs", "definitions", "properties", "patternProperties", "dependentSchemas":
		if n.Kind != jsonconfig.KindObject {
			return errors.New("MCP schema map shape is unsupported")
		}

		for _, child := range n.Members {
			if err := collectSchemaScopes(ctx, child.Value, base, false, resources, scopes); err != nil {
				return err
			}
		}
	case "allOf", "anyOf", "oneOf", "prefixItems":
		if n.Kind != jsonconfig.KindArray {
			return errors.New("MCP schema array shape is unsupported")
		}

		for _, child := range n.Elements {
			if err := collectSchemaScopes(ctx, child, base, false, resources, scopes); err != nil {
				return err
			}
		}
	case "items", "additionalProperties", "contains", "propertyNames", "unevaluatedItems", "unevaluatedProperties", "not", "if", "then", "else", "contentSchema":
		return collectSchemaScopes(ctx, n, base, false, resources, scopes)
	}

	return nil
}

func schemaURI(n *jsonconfig.Node) (*url.URL, error) {
	text, ok := n.Text()
	if !ok || len(text) > maxSchemaURIBytes || strings.ContainsAny(text, " \\\t\r\n") {
		return nil, errors.New("MCP schema reference URI is invalid")
	}
	// url.Parse does not validate percent escapes inside queries or opaque URIs.
	if _, err := url.PathUnescape(text); err != nil {
		return nil, errors.New("MCP schema reference URI is invalid")
	}

	u, err := url.Parse(text)
	if err != nil || strings.Contains(u.Host, "%") {
		return nil, errors.New("MCP schema reference URI is invalid")
	}

	return u, nil
}

func resolveSchemaURI(base, ref *url.URL) (*url.URL, error) {
	// A URN has no hierarchical path base for a relative document reference.
	if base.Opaque != "" && ref.Scheme == "" && (ref.Host != "" || ref.Path != "" || ref.RawQuery != "" || ref.ForceQuery) {
		return nil, errors.New("MCP schema relative reference base is unsupported")
	}

	resolved := base.ResolveReference(ref)
	if len(resolved.String()) > maxSchemaURIBytes {
		return nil, errors.New("MCP schema resolved URI limit")
	}

	return resolved, nil
}

func schemaResourceURI(u *url.URL) string {
	resource := *u
	resource.Fragment, resource.RawFragment = "", ""
	resource.Scheme = strings.ToLower(resource.Scheme)
	// URI host folding is ASCII-only. Unicode/IDNA mappings and IPv6 zones
	// must not collapse distinct resource identities through Unicode case folding.
	resource.Host = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, resource.Host)

	resource.RawPath = schemaURIEscapes(resource.EscapedPath())
	if resource.Opaque == "" && resource.Path != "" {
		// Decode unreserved escapes before removing dot segments, without
		// turning escaped path delimiters into separators.
		normalized := (&url.URL{}).ResolveReference(&url.URL{Path: resource.Path, RawPath: resource.RawPath})
		resource.Path, resource.RawPath = normalized.Path, normalized.RawPath
	}

	resource.RawQuery, resource.Opaque = schemaURIEscapes(resource.RawQuery), schemaURIEscapes(resource.Opaque)
	if resource.Scheme == "http" || resource.Scheme == "https" {
		if resource.Scheme == "http" && resource.Port() == "80" || resource.Scheme == "https" && resource.Port() == "443" {
			resource.Host = strings.TrimSuffix(resource.Host, ":"+resource.Port())
		}

		if resource.Path == "" && resource.Opaque == "" {
			resource.Path, resource.RawPath = "/", ""
		}
	}

	return resource.String()
}

// URI identity normalizes unreserved escapes, but preserves escaped delimiters:
// /a%2Fb and /a/b must never alias two different schema resources.
func schemaURIEscapes(text string) string {
	var out strings.Builder
	out.Grow(len(text))

	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) {
			var decoded [1]byte

			if _, err := hex.Decode(decoded[:], []byte(text[i+1:i+3])); err == nil {
				value := decoded[0]
				if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("-._~", rune(value)) {
					out.WriteByte(value)
				} else {
					out.WriteByte('%')
					out.WriteByte("0123456789ABCDEF"[value>>4])
					out.WriteByte("0123456789ABCDEF"[value&15])
				}

				i += 2

				continue
			}
		}

		out.WriteByte(text[i])
	}

	return out.String()
}
