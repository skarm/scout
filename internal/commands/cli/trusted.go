package cli

import (
	"errors"
	"io"
	"path/filepath"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/internal/commands/output"
)

const maxTrustedPreallocation = 8 << 20

// Operator-controlled baseline/cache files are never discovered in an artifact.
// Reject files inside either input, symlinks and special files. The parent
// directory is trusted operator configuration, not an artifact sandbox.
func readTrusted(name string, inputs []string, limit int) ([]byte, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}

	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}

	absolute = filepath.Join(parent, filepath.Base(absolute))

	for _, input := range inputs {
		if err := trustedInputBoundary(absolute, input); err != nil {
			return nil, err
		}
	}

	return readTrustedFile(parent, absolute, limit)
}

func trustedInputBoundary(absolute, input string) error {
	if fetch.IsRemote(input) {
		return nil
	}

	// Reading trusted settings and publishing reports need the same separation
	// from input files, hardlinks and directory aliases on the host filesystem.
	if _, err := output.Validate(absolute, []string{input}); err != nil {
		return errors.New("trusted configuration must be outside all inputs")
	}

	return nil
}

func readTrustedFile(parent, absolute string, limit int) ([]byte, error) {
	root, err := rootfs.Open(parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("invalid trusted configuration file")
	}

	data, err := readTrustedSized(io.LimitReader(f, int64(limit)+1), info.Size())
	if len(data) > limit {
		return nil, errors.New("trusted configuration limit")
	}

	return data, err
}

func readTrustedSized(reader io.Reader, size int64) ([]byte, error) {
	if size <= 512 || size > maxTrustedPreallocation {
		return io.ReadAll(reader)
	}

	// Keep room for an EOF probe. If the file grew after stat, continue
	// with the original bounded reader and preserve its error behavior.
	data := make([]byte, int(size)+1) //nolint:prealloc // The size of the exceptional growth tail is unknown until after the initial read.
	for offset := 0; offset < len(data); {
		n, err := reader.Read(data[offset:])

		offset += n
		if err == io.EOF {
			return data[:offset], nil
		}

		if err != nil {
			return data[:offset], err
		}
	}

	tail, err := io.ReadAll(reader)

	return append(data, tail...), err
}
