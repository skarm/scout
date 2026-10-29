package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Validate resolves an explicit destination and checks every local input before
// a scan starts. Its parent must exist. An existing regular report may be
// replaced; symbolic links, nonregular destinations and scan inputs may not.
// An empty localInputs is valid for stdin and remote captures.
func Validate(destination string, localInputs []string) (string, error) {
	name, existing, err := resolveReplacement(destination)
	if err != nil {
		return "", err
	}

	for _, input := range localInputs {
		if err := validateBoundary(name, existing, input); err != nil {
			return "", err
		}
	}

	return name, nil
}

// Write renders, syncs and closes a private sibling before replacing the report.
// A rendering, cancellation or publication failure preserves an existing report.
// It never deletes the old report as a fallback. Rename atomicity follows the
// target OS/filesystem; directory fsync and power-loss durability are not promised.
func Write(ctx context.Context, destination string, localInputs []string, render func(io.Writer) error) error {
	if ctx == nil || render == nil {
		return errors.New("report context and renderer are required")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	name, err := Validate(destination, localInputs)
	if err != nil {
		return err
	}

	return publishReplacement(ctx, name, localInputs, render)
}

func resolveReplacement(destination string) (string, os.FileInfo, error) {
	if destination == "" {
		return "", nil, errors.New("explicit report destination required")
	}

	absolute, err := filepath.Abs(destination)
	if err != nil {
		return "", nil, err
	}

	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", nil, fmt.Errorf("resolve existing report directory: %w", err)
	}

	info, err := os.Stat(parent)
	if err != nil {
		return "", nil, fmt.Errorf("inspect report directory: %w", err)
	}

	if !info.IsDir() {
		return "", nil, errors.New("report parent must be an existing directory")
	}

	name := filepath.Join(parent, filepath.Base(absolute))

	existing, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return name, nil, nil
	}

	if err != nil {
		return "", nil, fmt.Errorf("inspect report destination: %w", err)
	}

	if !existing.Mode().IsRegular() {
		return "", nil, errors.New("report destination must be a regular file, not a symlink or directory")
	}

	return name, existing, nil
}

func validateBoundary(destination string, existing os.FileInfo, input string) error {
	if input == "" {
		return errors.New("local scan input path must not be empty")
	}

	absolute, err := filepath.Abs(input)
	if err != nil {
		return err
	}

	info, statErr := os.Stat(absolute)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect scan input boundary: %w", statErr)
	}

	resolved, err := resolveInput(absolute)
	if err != nil {
		return err
	}

	if sameInputFile(destination, resolved, existing, info) {
		return errors.New("report must not replace a scan input or its hardlink")
	}

	return validateDirectoryBoundary(destination, info)
}

func validateDirectoryBoundary(destination string, info os.FileInfo) error {
	if info != nil && info.IsDir() {
		inside, err := insideDirectory(filepath.Dir(destination), info)
		if err != nil {
			return err
		}

		if inside {
			return errors.New("report must be outside every scanned directory")
		}
	}

	return nil
}

// Missing inputs still need diagnostic reports. Resolve their existing parent
// chain so an alias cannot hide an exact replacement of the missing input path.
func resolveInput(name string) (string, error) {
	var tail []string

	for {
		resolved, err := filepath.EvalSymlinks(name)
		if err == nil {
			for _, t := range slices.Backward(tail) {
				resolved = filepath.Join(resolved, t)
			}

			return resolved, nil
		}

		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve scan input boundary: %w", err)
		}

		parent := filepath.Dir(name)
		if parent == name {
			return "", fmt.Errorf("resolve scan input ancestor: %w", err)
		}

		tail = append(tail, filepath.Base(name))
		name = parent
	}
}

// Directory identities, rather than string prefixes, also cover resolved aliases
// and case variations on case-insensitive filesystems. Destination parents exist.
func insideDirectory(parent string, input os.FileInfo) (bool, error) {
	for {
		info, err := os.Stat(parent)
		if err != nil {
			return false, fmt.Errorf("inspect report ancestor: %w", err)
		}

		if os.SameFile(input, info) {
			return true, nil
		}

		next := filepath.Dir(parent)
		if next == parent {
			return false, nil
		}

		parent = next
	}
}

func publishReplacement(ctx context.Context, name string, localInputs []string, render func(io.Writer) error) (err error) {
	pattern := ".scout-report-*"
	if strings.HasPrefix(filepath.Base(name), ".scout-report-") {
		pattern = ".scout-publish-*"
	}

	file, err := os.CreateTemp(filepath.Dir(name), pattern)
	if err != nil {
		return fmt.Errorf("create private report: %w", err)
	}

	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}

		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary report: %w", removeErr))
		}
	}()

	closed, err = renderAndClose(ctx, file, render)
	if err != nil {
		return err
	}

	return replace(ctx, file.Name(), name, localInputs)
}

func replace(ctx context.Context, temporary, name string, localInputs []string) error {
	current, err := Validate(name, localInputs)
	if err != nil {
		return err
	}

	if current != name {
		return errors.New("report directory changed during rendering")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := os.Rename(temporary, name); err != nil {
		return fmt.Errorf("publish report: %w", err)
	}

	return nil
}

func sameInputFile(destination, input string, existing, info os.FileInfo) bool {
	return destination == input || existing != nil && info != nil && os.SameFile(existing, info)
}
