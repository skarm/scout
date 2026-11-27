package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

const (
	maxExclusionPatterns = 32
	maxExclusionBytes    = 256
)

var errSkillManifestScope = errors.New("skill exclusions require exactly one regular SKILL.md at the root")

// SkillExclusions holds immutable caller-supplied globs for one local skill.
type SkillExclusions struct {
	patterns   []string
	normalized []string
}

func CompileSkillExclusions(patterns []string) (SkillExclusions, error) {
	if len(patterns) == 0 || len(patterns) > maxExclusionPatterns {
		return SkillExclusions{}, errors.New("expected 1..32 skill exclusion patterns")
	}

	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > maxExclusionBytes || !utf8.ValidString(pattern) ||
			strings.ContainsAny(pattern, "\\:") || strings.ContainsFunc(pattern, unicode.IsControl) {
			return SkillExclusions{}, errors.New("invalid skill exclusion pattern")
		}

		for segment := range strings.SplitSeq(pattern, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return SkillExclusions{}, errors.New("skill exclusions require relative POSIX path patterns")
			}
		}

		glob := globPath(pattern)
		if _, err := path.Match(glob, ""); err != nil {
			return SkillExclusions{}, fmt.Errorf("invalid skill exclusion pattern %q", pattern)
		}

		for _, manifest := range []string{artifact.SkillManifest, strings.ToLower(artifact.SkillManifest)} {
			if matches, _ := path.Match(glob, manifest); matches {
				return SkillExclusions{}, errors.New("skill exclusions cannot match SKILL.md or skill.md")
			}
		}

		normalized = append(normalized, glob)
	}

	return SkillExclusions{patterns: slices.Clone(patterns), normalized: normalized}, nil
}

func (e SkillExclusions) Active() bool { return len(e.patterns) != 0 }

func (e SkillExclusions) Patterns() []string { return slices.Clone(e.patterns) }

func (e SkillExclusions) matches(name string) bool {
	if !e.Active() {
		return false
	}

	normalized := globPath(name)
	for _, pattern := range e.normalized {
		if matched, _ := path.Match(pattern, normalized); matched {
			return true
		}
	}

	return false
}

// path.Match reserves slash. NUL is impossible in either validated input, so
// replace slash on both sides to let wildcard matching cross directory levels.
func globPath(value string) string { return strings.ReplaceAll(value, "/", "\x00") }

func ReadSkill(ctx context.Context, target string, limits report.CaptureLimits, exclusions SkillExclusions) (artifact.Snapshot, error) {
	if err := limits.Validate(); err != nil {
		return artifact.Snapshot{}, err
	}

	if err := ctx.Err(); err != nil {
		return artifact.Snapshot{}, err
	}

	info, err := inspectInput(target)
	if err != nil {
		return artifact.Snapshot{}, err
	}

	if !info.IsDir() || !exclusions.Active() {
		err := errors.New("skill exclusions require one local skill directory")
		return invalidSkillSnapshot("file", nil, err), err
	}

	return readScopedDirectory(ctx, target, info, limits, exclusions)
}

func invalidSkillSnapshot(kind string, diagnostics []report.Diagnostic, err error) artifact.Snapshot {
	diagnostics = append(diagnostics, report.Diagnostic{
		Code: "invalid_skill_exclusion_scope", Path: ".", Message: err.Error(), AffectsScope: true,
	})

	return artifact.New(kind, nil, nil, diagnostics, false)
}

func (e SkillExclusions) validateRootManifest(entries []os.DirEntry) error {
	found := false

	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), artifact.SkillManifest) {
			continue
		}

		if e.matches(entry.Name()) {
			return errors.New("skill exclusions cannot match a skill manifest")
		}

		if !entry.Type().IsRegular() || found {
			return errSkillManifestScope
		}

		found = true
	}

	if !found {
		return errSkillManifestScope
	}

	return nil
}
