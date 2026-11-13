package shell

import (
	"maps"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

func plainGeneratedShellConditional(c *shellsyntax.Command) bool {
	return c.ExclusiveBranches && len(c.Words) == 0 && len(c.Redirects) == 0 && len(c.Assignments) == 0 && len(c.Invalidates) == 0
}

func (f *generatedShellFlow) clone() *generatedShellFlow {
	if f == nil {
		return nil
	}

	return &generatedShellFlow{cwd: f.cwd, previous: f.previous, files: maps.Clone(f.files)}
}

func (f *generatedShellFlow) intersect(other *generatedShellFlow) {
	if other == nil || f.cwd != other.cwd {
		f.reset()
		return
	}

	if f.previous != other.previous {
		f.previous = ""
	}

	for key, write := range f.files {
		if next, known := other.files[key]; !known || !write.sameVersion(next) {
			delete(f.files, key)
		}
	}
}

func (w generatedShellWrite) sameVersion(other generatedShellWrite) bool {
	if w.header != other.header || w.body != other.body || w.transforms != other.transforms || w.transformCount != other.transformCount ||
		w.confirmed != other.confirmed || w.foreignShebang != other.foreignShebang || !w.view.SameProjection(other.view) {
		return false
	}

	a, b := w.candidate, other.candidate
	if a == b {
		return true
	}

	if a == nil || b == nil || a.input != b.input || a.at != b.at || a.depth != b.depth ||
		a.functionBody != b.functionBody || a.gap != b.gap || a.reason != b.reason || !maps.Equal(a.variables, b.variables) {
		return false
	}

	if a.prior == nil || b.prior == nil {
		return a.prior == b.prior
	}

	return a.prior.sameVersion(*b.prior)
}
