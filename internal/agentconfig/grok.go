package agentconfig

import (
	"strings"

	"github.com/skarm/scout/internal/agentplugins"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

// GrokLegacyManifests is the order used for native and compatible package metadata.
func GrokLegacyManifests() []string {
	return []string{artifact.GrokPluginManifest, agentplugins.ManifestFile, artifact.ClaudePluginManifest}
}

func GrokMarketplaceIndex(root *jsonconfig.Node) bool {
	return root.GetOrEmpty("plugins").Kind == jsonconfig.KindArray
}

func GrokHookTarget(handler *jsonconfig.Node) *jsonconfig.Node {
	kind, _ := handler.Get("type").Text()

	var value *jsonconfig.Node

	switch kind {
	case "command":
		value = handler.Get("command")
	case "http":
		value = handler.Get("url")
	}

	if text, ok := value.Text(); ok && strings.TrimSpace(text) != "" {
		return value
	}

	return nil
}
