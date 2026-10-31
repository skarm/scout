package evaluation

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
)

func measureCase(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, tc Case, reviewer *scout.Scanner) (Result, error) {
	root := ""

	if len(tc.Files) > 0 {
		var err error

		root, err = materialize(ctx, tc.Files)
		if err != nil {
			return Result{}, err
		}

		defer func() { _ = os.RemoveAll(root) }()
	}

	result, _ := scanCase(ctx, scanner, gate, tc, caseTarget(tc, root))
	if reviewer != nil {
		reviewed, semantic := scanCase(ctx, reviewer, gate, tc, caseTarget(tc, root))
		result.Review = reviewResult(reviewed, semantic)
	}

	return result, nil
}

func caseTarget(tc Case, root string) scout.Target {
	if root != "" {
		return scout.Path(root)
	}

	return scout.Reader(tc.Path, strings.NewReader(tc.Content))
}

// Only validated relative regular files are written into a fresh private root.
// Executable metadata is retained for analysis; no case is ever executed.
func materialize(ctx context.Context, files []File) (string, error) {
	root, err := os.MkdirTemp("", "scout-evaluation-*")
	if err != nil {
		return "", errors.New("cannot create evaluation package")
	}

	for _, file := range files {
		if err := ctx.Err(); err != nil {
			_ = os.RemoveAll(root)
			return "", err
		}

		name := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			_ = os.RemoveAll(root)
			return "", errors.New("cannot materialize evaluation package")
		}

		if err := writePackageFile(name, file); err != nil {
			_ = os.RemoveAll(root)
			return "", err
		}
	}

	if err := verifyPackageTree(ctx, root, files); err != nil {
		_ = os.RemoveAll(root)

		if contextErr := ctx.Err(); contextErr != nil {
			return "", contextErr
		}

		return "", errors.New("filesystem cannot preserve evaluation package paths")
	}

	return root, nil
}

func verifyPackageTree(ctx context.Context, root string, files []File) error {
	expected := make(map[string]File, len(files))
	for _, file := range files {
		expected[file.Path] = file
	}

	entries, captured := 0, 0

	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if walkErr != nil {
			return walkErr
		}

		entries++
		if entries > MaxPackageEntries+1 {
			return errors.New("materialized package entry limit")
		}

		if entry.IsDir() {
			return nil
		}

		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}

		file, ok := expected[filepath.ToSlash(relative)]
		if !ok {
			return errors.New("materialized package path mismatch")
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		if err := verifyFileMetadata(file, info); err != nil {
			return err
		}

		captured++

		return nil
	})
	if err != nil {
		return err
	}

	if captured != len(expected) {
		return errors.New("materialized package file count mismatch")
	}

	return nil
}

func writePackageFile(name string, file File) error {
	mode := os.FileMode(0o600)
	if file.Executable {
		mode = 0o700
	}
	// Exclusive creation also rejects filesystem aliases that are not visible
	// in the portable namespace, such as generated Windows short names.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- Validated relative path under a new private package root.
	if err != nil {
		return errors.New("cannot create evaluation package file")
	}

	_, writeErr := io.WriteString(f, file.Content)
	info, statErr := f.Stat()

	closeErr := f.Close()
	if errors.Join(writeErr, statErr, closeErr) != nil {
		return errors.New("cannot write evaluation package file")
	}

	if err := verifyFileMetadata(file, info); err != nil {
		return errors.New("filesystem cannot preserve evaluation file metadata")
	}

	return nil
}

func verifyFileMetadata(file File, info os.FileInfo) error {
	if !info.Mode().IsRegular() || (info.Mode()&0o111 != 0) != file.Executable || info.Size() != int64(len(file.Content)) {
		return errors.New("evaluation file metadata mismatch")
	}

	return nil
}
