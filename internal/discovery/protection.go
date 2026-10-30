package discovery

import "path/filepath"

// Plan publication boundaries independently of traversal budgets. Only known
// configuration locations are protected, so ordinary reports in the selected
// home or project remain writable even when the inventory is incomplete.
func (b *builder) protectLocations() {
	if b.selects("codex") {
		b.protect(filepath.Join(b.options.Home, ".agents", "skills"))

		if b.options.CodexHome == "" {
			b.protect(filepath.Join(b.options.Home, ".codex"))
		} else {
			b.protect(b.options.CodexHome)
		}
	}

	if b.selects("claude-code") {
		b.protect(filepath.Join(b.options.Home, ".claude.json"))

		if b.options.ClaudeHome == "" {
			b.protect(filepath.Join(b.options.Home, ".claude"))
		} else {
			b.protect(b.options.ClaudeHome)
		}
	}

	if b.options.System {
		for _, agent := range []string{"codex", "claude-code"} {
			if b.selects(agent) {
				b.protect(systemRoot(agent))
			}
		}
	}
}

func (b *builder) protectProjectAncestors(dir string) {
	// Do not depend on discovering .git or on successful source reads: an early
	// stop must still protect possible inputs in the bounded ancestor chain.
	for range 64 {
		if b.selects("codex") {
			b.protect(filepath.Join(dir, ".codex"))
			b.protect(filepath.Join(dir, ".agents", "skills"))
		}

		if b.selects("claude-code") {
			b.protect(filepath.Join(dir, ".claude"))
			b.protect(filepath.Join(dir, ".mcp.json"))
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}

		dir = parent
	}
}

func (b *builder) protect(name string) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		b.issue("invalid_root", name)
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
