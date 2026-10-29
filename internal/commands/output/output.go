// Package output publishes complete reports and generated bundles through
// private sibling files. CreateNew never replaces an existing destination;
// Write permits replacement while protecting the caller's input paths.
// The destination directory is operator-controlled, not a sandbox against
// hostile same-user filesystem writers.
package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CreateNew publishes trusted generated content without consulting a scan input.
// It preserves create-only/private-file semantics and never installs a bundle.
func CreateNew(ctx context.Context, destination string, render func(io.Writer) error) error {
	if ctx == nil || render == nil {
		return errors.New("context and renderer are required")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	name, err := resolveDestination(destination)
	if err != nil {
		return err
	}

	return publish(ctx, name, render)
}

// renderAndClose completes the shared private-file rendering phase. The caller
// retains cleanup ownership and chooses its own atomic publication policy.
func renderAndClose(ctx context.Context, f *os.File, render func(io.Writer) error) (bool, error) {
	if err := render(f); err != nil {
		return false, fmt.Errorf("render report: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("sync report: %w", err)
	}

	err := f.Close()
	if err != nil {
		return true, fmt.Errorf("close report: %w", err)
	}

	return true, nil
}

func publish(ctx context.Context, name string, render func(io.Writer) error) (err error) {
	f, err := os.CreateTemp(filepath.Dir(name), ".scout-report-*")
	if err != nil {
		return fmt.Errorf("create private report: %w", err)
	}

	temporary := f.Name()

	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}

		if removeErr := os.Remove(temporary); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove report temporary file: %w", removeErr))
		}
	}()

	closed, err = renderAndClose(ctx, f, render)
	if err != nil {
		return err
	}

	if err = ctx.Err(); err != nil {
		return err
	}
	// Link is atomic with respect to destination existence. Unlike Rename, it
	// never replaces a regular file, symlink or concurrent writer's report.
	if err = os.Link(temporary, name); err != nil {
		return fmt.Errorf("publish new report without replacement: %w", err)
	}

	return nil
}

func resolveDestination(destination string) (string, error) {
	if destination == "" {
		return "", errors.New("explicit destination required")
	}

	absolute, err := filepath.Abs(destination)
	if err != nil {
		return "", err
	}

	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve existing report directory: %w", err)
	}

	name := filepath.Join(parent, filepath.Base(absolute))
	if _, err := os.Lstat(name); err == nil {
		return "", fmt.Errorf("report already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	return name, nil
}
