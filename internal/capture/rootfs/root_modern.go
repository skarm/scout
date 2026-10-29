//go:build !linux && !darwin && go1.24

// Package rootfs implements read-only, traversal-resistant local file access.
package rootfs

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

// Root uses Go 1.24's os.Root for OS-level traversal resistance. Linux additionally
// uses no-follow opens in its own backend. Only Linux is runtime-tested in the
// initial delivery; the cross-platform CI matrix must verify this backend.
type Root struct{ root *os.Root }

func Open(name string) (*Root, error) {
	r, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}

	return &Root{root: r}, nil
}

func (r *Root) Open(name string) (*os.File, error) {
	if !fs.ValidPath(name) || strings.Contains(name, `\`) {
		return nil, errors.New("invalid root-relative path")
	}

	before, err := r.root.Lstat(name)
	if err != nil {
		return nil, err
	}

	if !regularOrDirectory(before.Mode()) {
		return nil, errors.New("nonregular entry refused")
	}

	f, err := r.root.OpenFile(name, os.O_RDONLY|readFlags, 0)
	if err != nil {
		return nil, err
	}

	after, err := f.Stat()
	if err != nil {
		_ = f.Close() // Preserve the stat error when discarding the input.

		return nil, err
	}

	if !os.SameFile(before, after) || !regularOrDirectory(after.Mode()) {
		_ = f.Close() // The rejected input is discarded regardless of close errors.

		return nil, errors.New("entry changed during open")
	}

	return f, nil
}

func (r *Root) Close() error { return r.root.Close() }

func regularOrDirectory(mode fs.FileMode) bool { return mode.IsDir() || mode.IsRegular() }
