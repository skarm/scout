package discovery

import (
	"path/filepath"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

// Plan publication boundaries independently of traversal budgets. Only known
// configuration locations are protected, so ordinary reports in the selected
// home or project remain writable even when the inventory is incomplete.
func (b *builder) protectLocations() {
	if b.selects(report.HostCodex) {
		b.protect(filepath.Join(b.options.Home, ".agents", "skills"))

		if b.options.CodexHome == "" {
			b.protect(filepath.Join(b.options.Home, codexHomeDirectory))
		} else {
			b.protect(b.options.CodexHome)
		}
	}

	if b.selects(report.HostClaudeCode) {
		b.protect(filepath.Join(b.options.Home, claudeGlobalConfig))

		if b.options.ClaudeHome == "" {
			b.protect(filepath.Join(b.options.Home, claudeHomeDirectory))
		} else {
			b.protect(b.options.ClaudeHome)
		}
	}

	if b.options.System {
		for _, agent := range []string{report.HostCodex, report.HostClaudeCode} {
			if b.selects(agent) {
				b.protect(systemRoot(agent))
			}
		}
	}
}

func (b *builder) protectProjectAncestors(dir string) {
	// Do not depend on discovering .git or on successful source reads: an early
	// stop must still protect possible inputs in the bounded ancestor chain.
	for range maxDiscoveryAncestorDepth {
		if b.selects(report.HostCodex) {
			b.protect(filepath.Join(dir, codexHomeDirectory))
			b.protect(filepath.Join(dir, ".agents", "skills"))
		}

		if b.selects(report.HostClaudeCode) {
			b.protect(filepath.Join(dir, claudeHomeDirectory))
			b.protect(filepath.Join(dir, artifact.MCPConfig))
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
