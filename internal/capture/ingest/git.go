package ingest

import (
	"archive/zip"
	"context"
	"errors"

	"github.com/skarm/scout/internal/capture/archiveutil"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

// ReadGitTree captures regular files from the ZIP made by the Git fetcher.
// The generated ZIP provides a stable source digest. Its members are the
// top-level source inventory and retain their original repository paths.
func ReadGitTree(ctx context.Context, data []byte, limits report.CaptureLimits) (artifact.Snapshot, error) {
	tree, err := archiveutil.OpenZIP(ctx, data, limits.MaxEntries, limits.MaxPathBytes, limits.MaxDepth)
	if err != nil {
		return artifact.Snapshot{}, err
	}

	b := newBuilder(limits)

	for i, file := range tree.File {
		if err := ctx.Err(); err != nil {
			return b.snapshot("remote"), err
		}

		if i == limits.MaxFiles {
			b.issue(codeFileCountLimit, file.Name, messageFileCountLimit)
			break
		}

		if err := b.captureGitFile(ctx, file, len(data)); err != nil {
			return b.snapshot("remote"), err
		}
	}

	return b.snapshot("remote"), nil
}

func (b *builder) captureGitFile(ctx context.Context, file *zip.File, treeBytes int) error {
	// OpenZIP has already checked the ZIP32 envelope.
	size := int64(file.UncompressedSize)
	if file.Method != zip.Store || !file.Mode().IsRegular() || size > int64(treeBytes) {
		return errors.New("invalid Git tree file")
	}

	budget, code, message := b.fileBudget(size)
	if code != "" {
		b.skip(file.Name, "file", code, message, size)
		return nil
	}

	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	data, err := readBounded(ctx, reader, budget)
	if err != nil {
		return err
	}

	b.consumed += int64(len(data))
	b.addFileData(file.Name, data, file.Mode()&0o111 != 0)

	return nil
}
