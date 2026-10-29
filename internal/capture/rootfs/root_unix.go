//go:build linux || darwin

// Package rootfs implements read-only, traversal-resistant local file access.
package rootfs

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Root uses openat with O_NOFOLLOW for EACH path component on Linux and Darwin, not a check-then-
// open sequence. O_NONBLOCK prevents a swapped-in FIFO from hanging open.
type Root struct{ file *os.File }

func Open(name string) (*Root, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open-root", Path: name, Err: err}
	}

	return &Root{file: os.NewFile(uintptr(fd), name)}, nil
}

func (r *Root) Open(name string) (*os.File, error) {
	if !fs.ValidPath(name) || strings.Contains(name, `\`) {
		return nil, errors.New("invalid root-relative path")
	}

	parent := int(r.file.Fd())
	owned := -1

	parts := strings.Split(name, "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}

		fd, err := unix.Openat(parent, part, flags, 0)

		if owned >= 0 {
			_ = unix.Close(owned)
		}

		if err != nil {
			return nil, &os.PathError{Op: "openat", Path: name, Err: err}
		}

		parent, owned = fd, fd
	}

	return os.NewFile(uintptr(owned), name), nil
}
func (r *Root) Close() error { return r.file.Close() }
