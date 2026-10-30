package scout

import (
	"context"
	"os"
	"path/filepath"

	"github.com/skarm/scout/report"
)

// ScanEnvironment explicitly treats the selected local roots as one environment.
// Each root still gets its ordinary analysis. Additional source-bound observations
// relate declarations, skill references and capabilities across those analyses.
// The caller chooses one agent/project context; activation is not resolved.
// Roots must exist and must not overlap or alias each other. External traversal
// is not supported. ScanMany continues to inspect independent inputs.
func (s *Scanner) ScanEnvironment(ctx context.Context, targets []Target) (report.Run, error) {
	if err := s.validateTargets(ctx, targets); err != nil {
		return report.Run{}, err
	}

	call, cancel := context.WithTimeout(ctx, s.options.Limits.Timeout)
	defer cancel()

	if s.options.External != nil || !environmentRoots(call, targets) {
		return report.Run{}, &Error{Code: "invalid_environment_targets", Cause: ErrInvalidInput}
	}

	return s.executeWithin(call, targets, report.ScanOperation, CompareOptions{}, true)
}

func environmentRoots(ctx context.Context, targets []Target) bool {
	for _, target := range targets {
		if !target.IsLocal() {
			return false
		}
	}

	paths := make([]string, 0, len(targets))

	infos := make([]os.FileInfo, 0, len(targets))
	for _, target := range targets {
		if ctx.Err() != nil {
			return true // Execution retains a cancelled run without capturing bytes.
		}

		absolute, err := filepath.Abs(target.name)
		if err != nil {
			return false
		}

		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return false
		}

		info, err := os.Stat(resolved)
		if err != nil {
			return false
		}

		for i, prior := range paths {
			if os.SameFile(info, infos[i]) {
				return false
			}

			inside, insideErr := environmentContains(ctx, infos[i], resolved)

			contains, containsErr := environmentContains(ctx, info, prior)
			if ctx.Err() != nil {
				return true
			}

			if insideErr != nil || containsErr != nil || inside || contains {
				return false
			}
		}

		paths, infos = append(paths, resolved), append(infos, info)
	}

	return true
}

// Directory identities cover both selected aliases and case variations on
// case-insensitive filesystems. String prefixes alone cannot establish this.
func environmentContains(ctx context.Context, root os.FileInfo, file string) (bool, error) {
	if !root.IsDir() {
		return false, nil
	}

	for dir := filepath.Dir(file); ; dir = filepath.Dir(dir) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		info, err := os.Stat(dir)
		if err != nil {
			return false, err
		}

		if os.SameFile(root, info) {
			return true, nil
		}

		if filepath.Dir(dir) == dir {
			return false, nil
		}
	}
}
