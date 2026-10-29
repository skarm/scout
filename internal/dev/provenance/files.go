package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxArtifactBytes int64 = 512 << 20
	maxJSONBytes           = 16 << 20
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func projectRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("explicit project root required")
	}

	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}

	return filepath.EvalSymlinks(absolute)
}

func relativePath(root, path string) (string, error) {
	if path == "" {
		return "", errors.New("explicit artifact path required")
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.FromSlash(path))
	}

	relative, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return "", errors.New("artifact must be a local project file")
	}

	return filepath.ToSlash(relative), nil
}

func openFile(root, path string) (*os.File, error) {
	relative, err := relativePath(root, path)
	if err != nil {
		return nil, err
	}

	directory, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }() // The root handle owns no pending writes.

	file, err := directory.Open(filepath.FromSlash(relative))
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
		_ = file.Close() // Discard the rejected read-only input.
		return nil, errors.New("evidence must be a bounded regular file")
	}

	return file, nil
}

func artifactIdentity(ctx context.Context, root, path string) (artifact, error) {
	relative, err := relativePath(root, path)
	if err != nil {
		return artifact{}, err
	}

	file, err := openFile(root, relative)
	if err != nil {
		return artifact{}, err
	}
	defer func() { _ = file.Close() }() // The input file is read-only; read failures are handled separately.

	hash := sha256.New()
	if _, err = io.Copy(hash, contextReader{ctx: ctx, reader: file}); err != nil {
		return artifact{}, err
	}

	return artifact{Path: relative, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func verifyArtifact(ctx context.Context, root string, expected artifact) error {
	if !hexDigest(expected.SHA256, 64) {
		return errors.New("invalid artifact digest")
	}

	actual, err := artifactIdentity(ctx, root, expected.Path)
	if err != nil {
		return err
	}

	if actual.Path != expected.Path || actual.SHA256 != expected.SHA256 {
		return fmt.Errorf("artifact changed: %s", expected.Path)
	}

	return nil
}

func sourceInventory(ctx context.Context, root string) ([]file, []file, error) {
	product, err := ScannerRuntimeFiles(ctx, root)
	if err != nil {
		return nil, nil, err
	}

	developer, err := DeveloperRuntimeFiles(ctx, root)
	if err != nil {
		return nil, nil, err
	}

	a, err := sourceHashes(ctx, root, product)
	if err != nil {
		return nil, nil, err
	}

	b, err := sourceHashes(ctx, root, developer)

	return a, b, err
}

func sourceHashes(ctx context.Context, root string, paths []string) ([]file, error) {
	files := make([]file, 0, len(paths))
	for _, path := range paths {
		artifact, err := artifactIdentity(ctx, root, path)
		if err != nil {
			return nil, err
		}

		files = append(files, file{Path: artifact.Path, SHA256: artifact.SHA256})
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	return files, nil
}

func sourceState(ctx context.Context, root string) (string, bool, error) {
	command := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	command.Dir = root

	data, err := command.Output()
	if err != nil {
		return "", false, errors.New("cannot read source commit")
	}

	commit := strings.TrimSpace(string(data))
	if !hexDigest(commit, 40) && !hexDigest(commit, 64) {
		return "", false, errors.New("invalid Git source commit")
	}

	command = exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=normal")
	command.Dir = root

	data, err = command.Output()
	if err != nil {
		return "", false, errors.New("cannot read worktree state")
	}

	return commit, len(bytes.TrimSpace(data)) != 0, nil
}

func readJSONFile(root, path string) ([]byte, error) {
	file, err := openFile(root, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // The input file is read-only; read failures are handled separately.

	data, err := io.ReadAll(io.LimitReader(file, maxJSONBytes+1))
	if err != nil {
		return nil, err
	}

	if len(data) > maxJSONBytes || !utf8.Valid(data) {
		return nil, errors.New("JSON evidence size/encoding limit")
	}

	return data, nil
}

func decodeStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(out); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON evidence")
	}

	return nil
}

func hexDigest(text string, size int) bool {
	if len(text) != size || text != strings.ToLower(text) {
		return false
	}

	_, err := hex.DecodeString(text)

	return err == nil
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(data)
}
