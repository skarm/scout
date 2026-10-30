package dependencies

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type pipfileIndexes struct {
	public        map[string]bool
	defaultPublic bool
	valid         bool
}

// Missing provenance retains declaration semantics, as with other manifests.
// Explicit indexes must resolve through the captured source list; an invalid or
// ambiguous list must never identify a private fork as a public PyPI package.
func pipfileSources(sources *jsonconfig.Node) pipfileIndexes {
	if sources == nil {
		return pipfileIndexes{defaultPublic: true, valid: true}
	}

	if sources.Kind != jsonconfig.KindArray || len(sources.Elements) == 0 {
		return pipfileIndexes{}
	}

	indexes := pipfileIndexes{public: make(map[string]bool, len(sources.Elements))}
	for i, source := range sources.Elements {
		name, named := source.Get("name").Text()

		address, addressed := source.Get("url").Text()
		if _, duplicate := indexes.public[name]; duplicate || !named || name == "" || !addressed || address == "" {
			return pipfileIndexes{}
		}

		public := publicPythonRegistry(address)

		indexes.public[name] = public
		if i == 0 {
			indexes.defaultPublic = public
		}
	}

	indexes.valid = true

	return indexes
}

func (indexes pipfileIndexes) permits(declaration *jsonconfig.Node) bool {
	index := declaration.Get("index")
	if index == nil {
		return indexes.defaultPublic
	}

	name, ok := index.Text()

	return ok && indexes.public[name]
}

func pipfileExactVersion(declaration *jsonconfig.Node, version string, indexes pipfileIndexes) bool {
	if !indexes.permits(declaration) || !strings.HasPrefix(version, "==") || !exactPyVersion.MatchString(strings.TrimPrefix(version, "==")) {
		return false
	}

	for _, key := range []string{"markers", "git", "path", "file"} {
		if declaration.Get(key) != nil {
			return false
		}
	}

	return true
}

func publicPythonRegistry(address string) bool {
	return address == "https://pypi.org/simple" || address == "https://pypi.org/simple/"
}
