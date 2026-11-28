package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/osv"
)

const (
	smallTrustedReadBytes   = 512
	maxTrustedPreallocation = 8 << 20
)

// Operator-controlled baseline/cache files are never discovered in an artifact.
// Reject files inside either input, symlinks and special files. The parent
// directory is trusted operator configuration, not an artifact sandbox.
func readTrusted(name string, inputs []string, limit int) ([]byte, error) {
	f, size, err := openTrusted(name, inputs, int64(limit))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := readTrustedSized(io.LimitReader(f, int64(limit)+1), size)
	if len(data) > limit {
		return nil, errors.New("trusted configuration limit")
	}

	return data, err
}

func openTrusted(name string, inputs []string, limit int64) (*os.File, int64, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, 0, err
	}

	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, 0, err
	}

	absolute = filepath.Join(parent, filepath.Base(absolute))

	for _, input := range inputs {
		if err := trustedInputBoundary(absolute, input); err != nil {
			return nil, 0, err
		}
	}

	root, err := rootfs.Open(parent)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return nil, 0, err
	}

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		_ = f.Close()
		return nil, 0, errors.New("invalid trusted configuration file")
	}

	return f, info.Size(), nil
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

func (r *request) loadTrustedSnapshot(ctx context.Context, inputs []string) error {
	if r.settings.OSVSnapshotDir == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.settings.Scanner.Limits.Timeout)
	defer cancel()

	archives := make(map[string]osv.SnapshotArchive)

	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()

	for _, ecosystem := range osv.SnapshotEcosystems() {
		name := filepath.Join(r.settings.OSVSnapshotDir, ecosystem, "all.zip")

		f, size, err := openTrusted(name, inputs, osv.MaxSnapshotBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return errors.New("cannot read " + ecosystem + " OSV snapshot")
		}

		files = append(files, f)
		archives[ecosystem] = osv.SnapshotArchive{Reader: f, Size: size}
	}

	snapshot, err := osv.LoadSnapshot(ctx, archives)
	if err != nil {
		return err
	}

	r.settings.Scanner.Vulnerabilities.Snapshot = snapshot

	return nil
}

func readTrustedSized(reader io.Reader, size int64) ([]byte, error) {
	if size <= smallTrustedReadBytes || size > maxTrustedPreallocation {
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
