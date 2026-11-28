package agentconfig

import (
	"context"
	"iter"
	"path"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/textmatch"
)

const (
	OpenClawPackageKey = "openclaw"
	OpenClawInclude    = "$include"
)

// OpenClawPluginID identifies a native manifest without using its ID as a path.
func OpenClawPluginID(n *jsonconfig.Node) (string, bool) {
	id, _ := n.Get("id").Text()
	schema := n.Get("configSchema")

	return id, textmatch.Token(id, 128, "-._@/") && schema != nil && schema.Kind == jsonconfig.KindObject
}

func OpenClawPackageDeclared(metadata *jsonconfig.Node) bool {
	for _, field := range []string{"extensions", "hooks"} {
		if values := metadata.Get(field); values != nil && values.Kind == jsonconfig.KindArray && len(values.Elements) != 0 {
			return true
		}
	}

	return false
}

func OpenClawPackageID(n *jsonconfig.Node, fallback string) string {
	raw, _ := n.Get("name").Text()
	if name := path.Base(raw); name != "." && textmatch.Token(name, 128, "-._") {
		return name
	}

	return fallback
}

func OpenClawHookHandlers() []string {
	return []string{"handler.ts", "handler.js", "index.ts", "index.js"}
}

// OpenClawIncludes reports directives without interpreting their paths or merging configuration.
func OpenClawIncludes(ctx context.Context, config *jsonconfig.Node) iter.Seq[*jsonconfig.Node] {
	return func(yield func(*jsonconfig.Node) bool) {
		for item := range jsonconfig.Walk(ctx, config, jsonconfig.MaxDepth, jsonconfig.SourceOrder) {
			if include := item.Node.Get(OpenClawInclude); include != nil && !yield(include) {
				return
			}
		}
	}
}
