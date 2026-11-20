package discovery

import (
	"os"
	"path/filepath"
)

// sourcePathAliases keeps one spelling for the resolved traversal roots and
// their ancestors. Only siblings under a shared parent can be spelling
// aliases. The number of paths comes from the bounded discovery locations,
// independently of the number of files encountered in those locations.
type sourcePathAliases struct {
	spelling map[string]string
	children map[string][]string
	files    pathStats
}

func (p *sourcePathAliases) canonical(name string) string {
	if p.spelling == nil {
		p.spelling = make(map[string]string)
		p.children = make(map[string][]string)
		p.files = make(pathStats)
	}

	if known := p.spelling[name]; known != "" {
		return known
	}

	parent := filepath.Dir(name)
	if parent == name {
		return name
	}

	parent = p.canonical(parent)
	path := filepath.Join(parent, filepath.Base(name))

	known := p.spelling[path]
	if known == "" {
		known = p.register(parent, path)
		p.spelling[path] = known
	}

	p.spelling[name] = known

	return known
}

func (p *sourcePathAliases) register(parent, name string) string {
	for _, sibling := range p.children[parent] {
		info, _ := p.files.stat(name)
		other, _ := p.files.stat(sibling)

		if info != nil && other != nil && os.SameFile(info, other) {
			return sibling
		}
	}

	p.children[parent] = append(p.children[parent], name)

	return name
}
