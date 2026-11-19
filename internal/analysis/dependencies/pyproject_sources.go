package dependencies

import (
	"context"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type pyprojectSources struct {
	indexes       map[string]bool
	packages      map[string]*jsonconfig.Node
	defaultPublic bool
	valid         bool
}

// Missing provenance retains declaration semantics. Captured source overrides
// must not turn a private fork into a public PyPI advisory coordinate. This is
// deliberately not a resolver: conditional, ambiguous and non-index sources
// remain unresolved, and no external configuration or source is opened.
func pyprojectSourcePolicy(ctx context.Context, root *jsonconfig.Node) pyprojectSources {
	p := pyprojectSources{indexes: make(map[string]bool), packages: make(map[string]*jsonconfig.Node), defaultPublic: true, valid: true}

	uv := root.Get("tool").Get("uv")
	if uv != nil && uv.Kind != jsonconfig.KindObject {
		return pyprojectSources{}
	}

	if sources := uv.Get("sources"); sources != nil {
		if sources.Kind != jsonconfig.KindObject {
			return pyprojectSources{}
		}

		for _, source := range sources.Members {
			name := normalizePyPIName(source.Key)
			if _, duplicate := p.packages[name]; duplicate || ctx.Err() != nil {
				return pyprojectSources{}
			}

			p.packages[name] = source.Value
		}
	}

	if indexes := uv.Get("index"); indexes != nil {
		if indexes.Kind != jsonconfig.KindArray {
			return pyprojectSources{}
		}

		defaults := 0
		for _, index := range indexes.Elements {
			if ctx.Err() != nil || !p.addIndex(index, &defaults) {
				return pyprojectSources{}
			}
		}
	}

	p.valid = p.applyOptions(uv, root.Get("tool").Get("poetry"))

	return p
}

func (p *pyprojectSources) applyOptions(uv, poetry *jsonconfig.Node) bool {
	// Legacy uv index options and Poetry sources can also redirect PEP 621
	// declarations. Unsupported configuration is retained without public identity.
	if address := uv.Get("index-url"); address != nil {
		value, ok := address.Text()
		p.defaultPublic = p.defaultPublic && ok && publicPythonRegistry(value)
	}

	if extra := uv.Get("extra-index-url"); extra != nil {
		if extra.Kind != jsonconfig.KindArray {
			return false
		}

		for _, address := range extra.Elements {
			value, ok := address.Text()
			p.defaultPublic = p.defaultPublic && ok && publicPythonRegistry(value)
		}
	}

	if links := uv.Get("find-links"); links != nil && (links.Kind != jsonconfig.KindArray || len(links.Elements) != 0) {
		return false
	}

	if noIndex := uv.Get("no-index"); noIndex != nil && (noIndex.Kind != jsonconfig.KindBool || noIndex.Bool) {
		return false
	}

	if !poetryPublicSources(poetry.Get("source")) {
		return false
	}

	if noSources := uv.Get("no-sources"); noSources != nil {
		if noSources.Kind != jsonconfig.KindBool {
			return false
		}

		if noSources.Bool {
			p.packages = nil
		}
	}

	return true
}

// An explicit Poetry PyPI source omits its URL by definition. Keep the
// all-public case; private or ambiguous priority combinations need a resolver.
func poetryPublicSources(sources *jsonconfig.Node) bool {
	if sources == nil {
		return true
	}

	if sources.Kind != jsonconfig.KindArray {
		return false
	}

	seen := make(map[string]bool, len(sources.Elements))
	for _, source := range sources.Elements {
		name, named := source.Get("name").Text()

		name = strings.ToLower(name)
		if !named || name == "" || seen[name] {
			return false
		}

		seen[name] = true

		if priority := source.Get("priority"); priority != nil {
			value, ok := priority.Text()
			if !ok || !slices.Contains([]string{"primary", "supplemental", "explicit"}, value) {
				return false
			}
		}

		address, ok := source.Get("url").Text()
		if name == "pypi" && source.Get("url") == nil {
			continue
		}

		if !ok || !publicPythonRegistry(address) {
			return false
		}
	}

	return true
}

func (p *pyprojectSources) addIndex(index *jsonconfig.Node, defaults *int) bool {
	address, ok := index.Get("url").Text()
	if index.Kind != jsonconfig.KindObject || !ok || address == "" {
		return false
	}

	for _, flag := range []string{"explicit", "default"} {
		if value := index.Get(flag); value != nil && value.Kind != jsonconfig.KindBool {
			return false
		}
	}

	explicit := index.Get("explicit") != nil && index.Get("explicit").Bool

	isDefault := index.Get("default") != nil && index.Get("default").Bool
	if isDefault {
		*defaults++
		if *defaults > 1 {
			return false
		}
	}

	format, simple := index.Get("format").Text()
	public := publicPythonRegistry(address) && (index.Get("format") == nil || simple && format == "simple")

	if explicit && isDefault {
		p.defaultPublic = false
	}

	if !explicit || isDefault {
		p.defaultPublic = p.defaultPublic && public
	}

	if name := index.Get("name"); name != nil {
		value, named := name.Text()
		if _, duplicate := p.indexes[value]; !named || value == "" || duplicate {
			return false
		}

		p.indexes[value] = public
	}

	return true
}

func (p pyprojectSources) permits(pkg string) bool {
	if !p.valid {
		return false
	}

	if len(p.packages) == 0 {
		return p.defaultPublic
	}

	source := p.packages[normalizePyPIName(pkg)]
	if source == nil {
		return p.defaultPublic
	}

	// Even a public index with a marker/extra/group is conditional; do not
	// infer which branch a resolver would choose from a captured declaration.
	if source.Kind != jsonconfig.KindObject || len(source.Members) != 1 {
		return false
	}

	name, ok := source.Get("index").Text()

	return ok && p.indexes[name]
}
