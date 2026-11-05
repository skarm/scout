package devcli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/skarm/scout/internal/capture/rootfs"
)

// Resolve only the explicitly selected input symlink. Descendant access uses
// the same no-follow, nonblocking opens as capture, so a FIFO cannot block
// before callers can inspect the file type or observe cancellation.
func openInputFile(name string) (*os.File, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New("invalid input path")
	}

	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, errors.New("cannot resolve input")
	}

	root, err := rootfs.Open(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("cannot open input directory")
	}
	defer func() { _ = root.Close() }()

	file, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return nil, errors.New("cannot open input")
	}

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("input must be a regular file")
	}

	return file, nil
}
