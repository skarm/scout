package discovery

import "path/filepath"

// Plan publication boundaries independently of traversal budgets. Only known
// configuration locations are protected, so ordinary reports in the selected
// home or project remain writable even when the inventory is incomplete.
func (b *builder) protectLocations() {
	for _, agent := range b.agents {
		b.protectRelative(b.options.Home, agent.user)

		if override := *agent.homeOverride(&b.options); override != "" {
			b.protectRelative(override, agent.relocated)
		} else {
			b.protectRelative(b.options.Home, agent.defaultHome)
		}

		if root := agent.systemRoot(); b.options.System && root != "" {
			b.protect(root)
		}
	}
}

func (b *builder) protectProjectAncestors(dir string) {
	// Do not depend on discovering .git or on successful source reads: an early
	// stop must still protect possible inputs in the bounded ancestor chain.
	for range maxDiscoveryAncestorDepth {
		for _, agent := range b.agents {
			b.protectRelative(dir, agent.project)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}

		dir = parent
	}
}

func (b *builder) protectRelative(base string, paths []location) {
	for _, item := range paths {
		b.protect(filepath.Join(base, filepath.FromSlash(item.path)))
	}
}

func (b *builder) protect(name string) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		b.issue(codeInvalidRoot, name)
		return
	}

	if b.protected == nil {
		b.protected = map[string]bool{}
	}

	if !b.protected[absolute] {
		b.protected[absolute] = true
		b.out.protectedInputs = append(b.out.protectedInputs, absolute)
	}
}
