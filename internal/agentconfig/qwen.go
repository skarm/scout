package agentconfig

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	QwenManifest     = "qwen-extension.json"
	QwenContext      = "QWEN.md"
	QwenLocalContext = "QWEN.local.md"
)

func qwenHookTarget(n *jsonconfig.Node) *jsonconfig.Node {
	kind, _ := n.Get("type").Text()
	switch kind {
	case "command":
		return n.Get("command")
	case "http":
		return n.Get("url")
	case "prompt":
		return n.Get("prompt")
	default:
		return nil
	}
}

func QwenHookValid(n *jsonconfig.Node) bool {
	value, ok := qwenHookTarget(n).Text()
	return ok && strings.TrimSpace(value) != ""
}

// QwenExtensionOperand resolves only a leading extension-root variable and
// path separators. The caller still validates the captured relative path.
func QwenExtensionOperand(value string) (string, bool) {
	raw, ok := strings.CutPrefix(value, ExtensionPath)
	if !ok {
		raw, ok = strings.CutPrefix(value, "${CLAUDE_PLUGIN_ROOT}")
	}

	if !ok {
		return "", false
	}

	raw = strings.NewReplacer("${/}", "/", "${pathSeparator}", "/").Replace(raw)
	rel, ok := strings.CutPrefix(raw, "/")

	return rel, ok && !strings.Contains(rel, "$")
}

func QwenPortableSSE(n *jsonconfig.Node) bool {
	value, _ := n.Get("type").Text()
	return value == "sse"
}
