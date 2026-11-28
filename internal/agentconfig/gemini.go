package agentconfig

import (
	"strings"

	"github.com/skarm/scout/internal/textmatch"
)

const (
	GeminiManifest      = "gemini-extension.json"
	GeminiExtensionPath = "${extensionPath}"
	GeminiContext       = "GEMINI.md"
	GeminiContextField  = "contextFileName"
	GeminiHTTPURL       = "httpUrl"
)

func ValidGeminiExtension(name, version string) bool {
	return textmatch.Slug(name, 128) && strings.TrimSpace(version) != ""
}

// GeminiHookSetting distinguishes legacy settings from hook events.
func GeminiHookSetting(name string) bool {
	return name == "enabled" || name == "disabled" || name == "notifications"
}
