package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/skarm/scout/internal/capture/rootfs"
)

const maxKnowledgeBinaryBytes = 512 << 20

// Stage the trusted Scout executable once so every child runs the bytes named
// in the receipt, even if a concurrent build replaces the original path.
func stageKnowledgeBinary(ctx context.Context, path, workspace string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}

	executable, err := exec.LookPath(absolute)
	if err != nil {
		return "", "", err
	}

	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", "", err
	}

	root, err := rootfs.Open(filepath.Dir(resolved))
	if err != nil {
		return "", "", err
	}
	defer func() { _ = root.Close() }()

	input, err := root.Open(filepath.Base(resolved))
	if err != nil {
		return "", "", err
	}
	defer func() { _ = input.Close() }()

	staged := filepath.Join(workspace, filepath.Base(executable))

	digest, err := copyKnowledgeBinary(input, staged)
	if err != nil {
		return "", "", err
	}

	return staged, digest, ctx.Err()
}

func copyKnowledgeBinary(input *os.File, path string) (string, error) {
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxKnowledgeBinaryBytes {
		return "", errors.New("knowledge runtime requires a bounded regular Scout binary")
	}

	//nolint:gosec // G302,G304: the private copy must be executable and its parent is a fresh private directory.
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, info.Size()+1))

	if err := errors.Join(copyErr, output.Close()); err != nil {
		return "", err
	}

	after, err := input.Stat()
	if err != nil || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("selected Scout binary changed during capture")
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
