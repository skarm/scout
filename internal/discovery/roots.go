package discovery

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
)

// RootBinding records the selected path and its resolved filesystem location.
type RootBinding struct {
	Path            string `json:"path"`
	Resolved        string `json:"resolved"`
	ProjectBoundary string `json:"project_boundary,omitempty"`
}

// PinRoots binds snapshot discovery to its selected paths. A missing directory
// keeps the resolved location of its existing prefix so removals remain visible.
// Extra paths are operator include/exclude filters, not discovery roots.
func (o *Options) PinRoots(saved []RootBinding, extra ...string) ([]RootBinding, error) {
	projects := make([]string, 0, len(o.Projects))
	for _, name := range o.Projects {
		absolute, err := filepath.Abs(name)
		if err != nil {
			return nil, err
		}

		projects = append(projects, absolute)
	}

	paths := append([]string{o.Home}, projects...)
	for _, agent := range selectedAgents(o.Agent) {
		if override := *agent.homeOverride(o); override != "" {
			paths = append(paths, override)
		}

		if root := agent.systemRoot(); o.System && root != "" {
			paths = append(paths, root)
		}
	}

	paths = append(paths, extra...)

	bound := make(map[string]string, len(paths))
	boundaries := make(map[string]string, len(projects))

	bindings := make([]RootBinding, 0, len(paths))
	for _, name := range paths {
		absolute, err := filepath.Abs(name)
		if err != nil {
			return nil, err
		}

		if _, seen := bound[absolute]; seen {
			continue
		}

		resolved, err := resolvePath(absolute)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve discovery snapshot path %q: %w", absolute, err)
		}

		binding := RootBinding{Path: absolute, Resolved: resolved}
		if slices.Contains(projects, absolute) {
			binding.ProjectBoundary = projectBoundary(resolved, o.Home)
			boundaries[resolved] = binding.ProjectBoundary
		}

		bound[absolute] = resolved

		bindings = append(bindings, binding)
	}

	if saved != nil && !slices.Equal(bindings, saved) {
		return nil, errors.New("saved discovery paths resolve differently or the project boundary changed; select explicit roots or use --candidate to compare captured bytes")
	}

	for _, binding := range bindings {
		bound[binding.Resolved] = binding.Resolved
	}

	o.boundRoots = bound
	o.projectBoundaries = boundaries

	return bindings, nil
}

func projectBoundary(dir, home string) string {
	for range maxDiscoveryAncestorDepth {
		next := projectParent(dir, home)
		if next == "" {
			return dir
		}

		dir = next
	}

	return ""
}

func (o Options) resolveRoot(absolute string) (string, error) {
	resolved, err := filepath.EvalSymlinks(absolute)
	if expected, bound := o.boundRoots[absolute]; err == nil && bound && resolved != expected {
		return "", fmt.Errorf("discovery root %q resolves to a different path", absolute)
	}

	return resolved, err
}
