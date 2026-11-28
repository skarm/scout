package agentconfig

import (
	"strings"

	"github.com/skarm/scout/internal/textmatch"
)

const (
	ExtensionPath         = "${extensionPath}"
	ExtensionContextField = "contextFileName"
	StreamableHTTPURL     = "httpUrl"
)

func ValidNamedExtension(name, version string) bool {
	return textmatch.Slug(name, 128) && strings.TrimSpace(version) != ""
}

// HookSetting distinguishes legacy settings from hook events.
func HookSetting(name string) bool {
	return name == "enabled" || name == "disabled" || name == "notifications"
}
