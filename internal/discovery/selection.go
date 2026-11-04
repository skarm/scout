package discovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// Filters narrows an already captured inventory. Paths are explicit operator
// selections; neither includes nor component metadata can expand its roots.
type Filters struct {
	Kinds        []string `json:"kinds,omitempty"`
	IncludePaths []string `json:"include_paths,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

// Selection records the requested scope separately from inventory completeness.
type Selection struct {
	Filters
	OriginalTargets int `json:"original_targets"`
}

// Select retains the full inventory and its issues, narrowing only scan targets.
// Exclusion removes an entire overlapping root: it never silently scans an
// excluded descendant. A kind filter selects individual component paths instead
// of broad cache/skill roots, allowing more precise inclusion and exclusion.
func Select(ctx context.Context, snapshot Snapshot, filters Filters) (Snapshot, error) {
	if ctx == nil {
		return snapshot, errors.New("selection context required")
	}

	if len(filters.Kinds)+len(filters.IncludePaths)+len(filters.ExcludePaths) == 0 {
		return snapshot, nil
	}

	if err := filters.resolve(); err != nil {
		return snapshot, err
	}

	candidates := snapshot.Targets
	if len(filters.Kinds) != 0 {
		candidates = nil

		roots := make(map[string]bool, len(snapshot.Targets))
		for _, root := range snapshot.Targets {
			roots[root] = true
		}

		for _, component := range snapshot.Components {
			if err := ctx.Err(); err != nil {
				return snapshot, err
			}

			if slices.Contains(filters.Kinds, component.Kind) && coveredBy(roots, component.Path) {
				candidates = append(candidates, component.Path)
			}
		}
	}

	targets, err := filterTargets(ctx, candidates, filters)
	if err != nil {
		return snapshot, err
	}

	b := builder{ctx: ctx, out: Snapshot{Targets: targets}}
	if err := b.compactTargets(); err != nil {
		return snapshot, err
	}

	snapshot.Selection = &Selection{Filters: filters, OriginalTargets: len(snapshot.Targets)}
	snapshot.Targets = b.out.Targets
	snapshot.Limitations = append(slices.Clone(snapshot.Limitations), "Explicit filters narrow scan targets only. Inventory completeness does not mean every discovered component was selected for scanning. Exclusion removes entire overlapping scan roots.")

	return snapshot, nil
}

func filterTargets(ctx context.Context, candidates []string, filters Filters) ([]string, error) {
	selected := make(map[string]bool)
	paths := selectionFilesystem{ctx: ctx, entries: make(map[string]os.FileInfo)}

	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		includes := filters.IncludePaths
		if len(includes) == 0 {
			includes = []string{candidate}
		}

		for _, include := range includes {
			name, err := paths.intersect(candidate, include)
			if err != nil {
				return nil, err
			}

			if name == "" {
				continue
			}

			excluded, err := paths.overlapsAny(filters.ExcludePaths, name)
			if err != nil {
				return nil, err
			}

			if !excluded {
				selected[name] = true
			}
		}
	}

	targets := make([]string, 0, len(selected))
	for name := range selected {
		targets = append(targets, name)
	}

	slices.Sort(targets)

	return targets, nil
}

func (f *Filters) resolve() error {
	for _, values := range [][]string{f.Kinds, f.IncludePaths, f.ExcludePaths} {
		if len(values) > 32 {
			return errors.New("at most 32 values per discovery filter")
		}
	}

	for _, kind := range f.Kinds {
		if !slices.Contains([]string{"skill", "plugin", "mcp-server", "command"}, kind) {
			return errors.New("kind must be skill, plugin, mcp-server or command")
		}
	}

	f.Kinds = slices.Clone(f.Kinds)

	var err error
	if f.IncludePaths, err = selectionPaths(f.IncludePaths); err != nil {
		return err
	}

	f.ExcludePaths, err = selectionPaths(f.ExcludePaths)

	return err
}

func selectionPaths(values []string) ([]string, error) {
	result := make([]string, len(values))
	for i, name := range values {
		if name == "" || len(name) > 4096 {
			return nil, errors.New("discovery path filters require nonempty bounded paths")
		}

		absolute, err := filepath.Abs(name)
		if err != nil {
			return nil, err
		}

		resolved, err := resolveSelectionPath(absolute)
		if err != nil {
			return nil, err
		}

		result[i] = resolved
	}

	return result, nil
}

// A missing suffix must not hide an existing symlink ancestor. Resolve the
// existing prefix before retaining names that have not been created yet.
func resolveSelectionPath(name string) (string, error) {
	var tail []string

	for {
		resolved, err := filepath.EvalSymlinks(name)
		if err == nil {
			for _, part := range slices.Backward(tail) {
				resolved = filepath.Join(resolved, part)
			}

			return resolved, nil
		}

		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("cannot resolve discovery path filter")
		}

		// A dangling link exists: it must not be peeled off as if it were
		// merely an absent filename beneath the discovered root.
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("cannot resolve discovery path filter")
		}

		parent := filepath.Dir(name)
		if parent == name {
			return "", errors.New("cannot resolve discovery path filter ancestor")
		}

		tail = append(tail, filepath.Base(name))
		name = parent
	}
}

func coveredBy(roots map[string]bool, name string) bool {
	for {
		if roots[name] {
			return true
		}

		parent := filepath.Dir(name)
		if parent == name {
			return false
		}

		name = parent
	}
}

type selectionFilesystem struct {
	ctx     context.Context
	entries map[string]os.FileInfo
}

func (p *selectionFilesystem) intersect(root, selected string) (string, error) {
	if contains, err := p.contains(selected, root); err != nil || contains {
		if err != nil {
			return "", err
		}

		return root, nil
	}

	if contains, err := p.contains(root, selected); err != nil || contains {
		if err != nil {
			return "", err
		}

		return selected, nil
	}

	return "", nil
}

func (p *selectionFilesystem) overlapsAny(roots []string, name string) (bool, error) {
	for _, root := range roots {
		if intersection, err := p.intersect(root, name); err != nil || intersection != "" {
			return intersection != "", err
		}
	}

	return false, nil
}

// Canonical symlink resolution does not normalize case or Unicode spelling.
// Compare existing ancestor identities as well, including for missing suffixes.
// Cached stats keep independent filters from repeatedly probing shared parents.
func (p *selectionFilesystem) contains(root, name string) (bool, error) {
	if within(root, name) {
		return true, nil
	}

	rootInfo, err := p.stat(root)
	if err != nil || rootInfo == nil {
		return false, err
	}

	for {
		if err := p.ctx.Err(); err != nil {
			return false, err
		}

		info, err := p.stat(name)
		if err != nil {
			return false, err
		}

		if info != nil && os.SameFile(rootInfo, info) {
			return true, nil
		}

		parent := filepath.Dir(name)
		if parent == name {
			return false, nil
		}

		name = parent
	}
}

func (p *selectionFilesystem) stat(name string) (os.FileInfo, error) {
	if info, ok := p.entries[name]; ok {
		return info, nil
	}

	info, err := os.Stat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot inspect discovery path filter or scan root")
	}

	p.entries[name] = info

	return info, nil
}
