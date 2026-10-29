//go:build !coreonly

package frontend

import (
	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/internal/syntax/language"
)

func BackendFor(format string) Backend {
	b := Backend{Format: format, Available: true}

	switch format {
	case language.Python:
		b.Name, b.Version = "tree-sitter-python", buildinfo.ModuleVersion("github.com/tree-sitter/tree-sitter-python")

		b.Available = pythonAvailable()
		if !b.Available {
			b.Reason = "Python grammar requires CGO-enabled build"
		}
	case language.YAML:
		b.Name, b.Version = "go-yaml", buildinfo.ModuleVersion("go.yaml.in/yaml/v3")
	case language.TOML:
		b.Name, b.Version = "go-toml", buildinfo.ModuleVersion("github.com/pelletier/go-toml/v2")
	default:
		b.Available = false
		b.Reason = "unknown format"
	}

	return b
}
