package artifactpath

import (
	"path"
	"strings"
)

// Reference accepts only portable paths. It never performs decoding, expansion,
// filesystem lookup or resolution against the scanner's working directory.
func Reference(raw string, requireDot bool) (string, string) {
	if raw == "" {
		return "", "empty_reference"
	}

	if strings.ContainsAny(raw, "\\:\x00\r\n\t") || strings.HasPrefix(raw, "/") {
		return "", "nonlocal_reference"
	}

	if strings.ContainsAny(raw, "$~*?[]{}") {
		return "", "symbolic_reference"
	}

	if requireDot && raw != "." && !strings.HasPrefix(raw, "./") {
		return "", "relative_prefix_required"
	}

	clean := path.Clean(raw)
	if strings.HasPrefix(clean+"/", "../") {
		return "", "outside_package"
	}

	return clean, ""
}
