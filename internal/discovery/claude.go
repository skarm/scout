package discovery

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func (t *tree) claudeHooks(hooks *jsonconfig.Node, file string) {
	if hooks == nil {
		return
	}

	if hooks.Kind != jsonconfig.KindObject {
		t.b.issue(codeInvalidPluginHooks, t.absolute(file))
		return
	}

	for _, event := range hooks.Members {
		if !t.b.step(t.absolute(file)) {
			return
		}

		if event.Value.Kind != jsonconfig.KindArray {
			t.b.issue(codeInvalidPluginHooks, t.absolute(file))
			continue
		}

		t.groupedHookItems(event, file, "/hooks/"+pointer(event.Key), claudeHook)
	}
}

func claudeHook(n *jsonconfig.Node) bool {
	kind, _ := n.Get("type").Text()

	field := kind
	switch kind {
	case "command", "prompt":
	case "http":
		field = "url"
	case "agent":
		field = "prompt"
	case "mcp_tool":
		return true
	default:
		return false
	}

	value, _ := n.Get(field).Text()

	return strings.TrimSpace(value) != ""
}
