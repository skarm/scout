// Package ingest captures untrusted local inputs without executing their code.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/capture/archiveutil"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/report"
)

var errEmpty = errors.New("input contains no files")

type builder struct {
	limits      report.CaptureLimits
	files       []artifact.File
	skipped     []report.File
	diagnostics []report.Diagnostic
	complete    bool
	consumed    int64
	entries     int
	fileEntries int
	names       archiveutil.Namespace
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

// Read accepts only an explicit local path. No URL, user configuration, ignore
// file, archive hook, or project command is evaluated.
func Read(ctx context.Context, target string, limits report.CaptureLimits) (artifact.Snapshot, error) {
	if err := limits.Validate(); err != nil {
		return artifact.Snapshot{}, err
	}

	if err := ctx.Err(); err != nil {
		return artifact.Snapshot{}, err
	}

	info, err := inspectInput(target)
	if err != nil {
		return artifact.Snapshot{}, err
	}

	if info.IsDir() {
		return readDirectory(ctx, target, info, limits)
	}

	return readFile(ctx, target, info, limits)
}

func newBuilder(l report.CaptureLimits) *builder {
	return &builder{limits: l, complete: true, names: archiveutil.Namespace{MaxNodes: l.MaxEntries}}
}

func inspectInput(target string) (os.FileInfo, error) {
	if target == "" || strings.Contains(target, "://") {
		return nil, errors.New("an explicit local file, directory or ZIP path is required; remote inputs are not implemented")
	}

	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("inspect input: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return nil, errors.New("input must be a regular file or directory, not a link or special file")
	}

	return info, nil
}

func readFile(ctx context.Context, target string, info os.FileInfo, limits report.CaptureLimits) (artifact.Snapshot, error) {
	if strings.EqualFold(filepath.Ext(target), ".zip") {
		data, err := readSelectedFile(ctx, target, info, min(limits.MaxArchiveBytes, limits.MaxTotalBytes))
		if err != nil {
			return artifact.Snapshot{}, err
		}

		name := filepath.Base(target)
		if err := ValidatePath(name, limits.MaxPathBytes, limits.MaxDepth); err != nil {
			return artifact.Snapshot{}, fmt.Errorf("invalid input filename: %w", err)
		}
		// Preserve the exact container, including metadata and padding. Member
		// extraction is a separate, bounded stage shared with nested archives.
		return artifact.New("file", []artifact.File{artifact.NewFile(name, data, info.Mode()&0o111 != 0)}, nil, nil, true), nil
	}

	b := newBuilder(limits)

	name := filepath.Base(target)
	if err := ValidatePath(name, limits.MaxPathBytes, limits.MaxDepth); err != nil {
		return artifact.Snapshot{}, fmt.Errorf("invalid input filename: %w", err)
	}

	if info.Size() > limits.MaxFileBytes {
		b.skip(name, "file", "file_size_limit", "File exceeds the per-file budget; no prefix was scanned.", info.Size())
		return b.snapshot("file"), nil
	}

	data, err := readSelectedFile(ctx, target, info, limits.MaxFileBytes)
	if err != nil {
		return artifact.Snapshot{}, err
	}

	b.files = append(b.files, artifact.NewFile(name, data, info.Mode()&0o111 != 0))

	return b.snapshot("file"), nil
}

func (b *builder) snapshot(kind string) artifact.Snapshot {
	return artifact.New(kind, b.files, b.skipped, b.diagnostics, b.complete)
}

func (b *builder) issue(code, path, message string) {
	b.complete = false
	b.diagnostics = append(b.diagnostics, report.Diagnostic{
		Code:         code,
		Path:         path,
		Message:      message,
		AffectsScope: true,
	})
}

func (b *builder) skip(name, kind, code, message string, size int64) {
	b.skipped = append(b.skipped, report.File{Path: name, Kind: kind, Size: size, Status: "skipped", Reason: code})
	b.issue(code, name, message)
}

func (b *builder) countEntry(name string) bool {
	b.entries++
	if b.entries > b.limits.MaxEntries {
		b.issue("entry_limit", name, "Inventory stopped at the entry limit; remaining entries are unknown.")
		return false
	}

	return true
}

func (b *builder) captureFile(ctx context.Context, root *rootfs.Root, name string) {
	f, err := root.Open(name)
	if err != nil {
		b.skip(name, "file", "file_unreadable", "File could not be opened safely.", -1)
		return
	}
	defer func() { _ = f.Close() }()

	b.captureOpenFile(ctx, f, name)
}

func (b *builder) captureOpenFile(ctx context.Context, f *os.File, name string) {
	before, err := f.Stat()
	if err != nil {
		b.skip(name, "file", "file_unreadable", "File metadata could not be read.", -1)
		return
	}

	if !before.Mode().IsRegular() {
		b.skip(name, "special", "nonregular_refused", "Entry was not a regular file at capture time.", -1)
		return
	}

	budget, code, message := b.fileBudget(before.Size())
	if code != "" {
		b.skip(name, "file", code, message, before.Size())
		return
	}

	data, err := readBounded(ctx, f, budget)

	b.consumed += int64(len(data))
	if err != nil {
		b.skip(name, "file", "file_read_error", "Bounded file capture failed; no prefix was scanned.", before.Size())
		return
	}

	after, err := f.Stat()
	if err != nil || changed(before, after, int64(len(data))) {
		b.skip(name, "file", "file_changed", "File changed while being captured; captured bytes were discarded.", before.Size())
		return
	}

	b.files = append(b.files, artifact.NewFile(name, data, before.Mode()&0o111 != 0))
}

func (b *builder) fileBudget(size int64) (int64, string, string) {
	budget := min(b.limits.MaxFileBytes, b.limits.MaxTotalBytes-b.consumed)
	if size > b.limits.MaxFileBytes {
		return budget, "file_size_limit", "File exceeds the per-file budget; no prefix was scanned."
	}

	if budget <= 0 || size > budget {
		return budget, "total_size_limit", "Aggregate byte budget exhausted; file was not captured."
	}

	return budget, "", ""
}

func (b *builder) walkDirectory(ctx context.Context, root *rootfs.Root) error {
	queue := []string{"."}

	stop := false
	for len(queue) > 0 && !stop {
		if err := ctx.Err(); err != nil {
			return err
		}

		dir := queue[0]
		queue = queue[1:]

		limited, err := b.captureDirectory(ctx, root, dir, &queue)
		if err != nil {
			return err
		}

		stop = limited
	}

	return nil
}

func (b *builder) captureDirectory(ctx context.Context, root *rootfs.Root, dir string, queue *[]string) (bool, error) {
	f, err := root.Open(dir)
	if err != nil {
		b.issue("directory_unreadable", dir, "Directory could not be opened safely; its contents are unknown.")
		return false, nil //nolint:nilerr // The recorded issue preserves this partial capture; readable sibling directories must continue.
	}

	entries, limited, readErr := b.directoryEntries(ctx, f, dir)
	_ = f.Close()

	if readErr != nil {
		return false, readErr
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	entryLimit, visitErr := b.visitDirectoryEntries(ctx, root, dir, entries, queue)
	if visitErr != nil {
		return false, visitErr
	}

	return limited || entryLimit, nil
}

func (b *builder) visitDirectoryEntries(ctx context.Context, root *rootfs.Root, dir string, entries []os.DirEntry, queue *[]string) (bool, error) {
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if b.visitEntry(ctx, root, dir, entry, queue) {
			return true, nil
		}
	}

	return false, nil
}

func (b *builder) visitEntry(ctx context.Context, root *rootfs.Root, dir string, entry os.DirEntry, queue *[]string) bool {
	name := entry.Name()
	if dir != "." {
		name = dir + "/" + name
	}

	if !b.inventoryEntry(name, entry.IsDir()) {
		return false
	}

	if entry.Type()&os.ModeSymlink != 0 {
		b.skip(name, "symlink", "symlink_refused", "Symbolic links are not followed.", -1)
		return false
	}

	if entry.Type() != 0 && !entry.IsDir() {
		b.skip(name, "special", "special_file_refused", "Sockets, devices and other special files are not read.", -1)
		return false
	}

	if entry.IsDir() {
		*queue = append(*queue, name)
		return false
	}

	b.fileEntries++
	if b.fileEntries > b.limits.MaxFiles {
		b.issue("file_count_limit", name, "File count budget exhausted; remaining file contents were not captured.")

		return true
	}

	b.captureFile(ctx, root, name)

	return false
}

func (b *builder) inventoryEntry(name string, directory bool) bool {
	if err := ValidatePath(name, b.limits.MaxPathBytes, b.limits.MaxDepth); err != nil {
		b.skip(name, "unknown", "invalid_path", "Entry has an unsupported or ambiguous path; descendants were not visited.", -1)
		return false
	}

	if err := b.names.Add(name, directory); err != nil {
		b.skip(name, "unknown", "path_collision", "Entry conflicts with another portable path; descendants were not visited.", -1)
		return false
	}

	return true
}

func (b *builder) directoryEntries(ctx context.Context, f *os.File, dir string) ([]os.DirEntry, bool, error) {
	// Read in bounded chunks; os.ReadDir would allocate every entry at once.
	entries := make([]os.DirEntry, 0)

	for {
		if err := ctx.Err(); err != nil {
			return entries, false, err
		}

		batch, readErr := f.ReadDir(64)
		limited := false

		for _, entry := range batch {
			if !b.countEntry(dir) {
				limited = true
				break
			}

			entries = append(entries, entry)
		}

		if limited || readErr != nil {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				b.issue("directory_read_error", dir, "Directory enumeration was incomplete.")
			}

			return entries, limited, nil
		}
	}
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(p)
}

func readSelectedFile(ctx context.Context, target string, info os.FileInfo, maxBytes int64) ([]byte, error) {
	if info.Size() < 0 || info.Size() > maxBytes {
		return nil, errors.New("input exceeds byte budget")
	}

	root, err := rootfs.Open(filepath.Dir(target))
	if err != nil {
		return nil, fmt.Errorf("open input parent: %w", err)
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(target))
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = f.Close() }()

	return readSelectedOpenFile(ctx, f, info, maxBytes)
}

func readSelectedOpenFile(ctx context.Context, f *os.File, info os.FileInfo, maxBytes int64) ([]byte, error) {
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !before.Mode().IsRegular() || !os.SameFile(info, before) {
		return nil, errors.New("input changed before capture")
	}

	data, err := readBounded(ctx, f, maxBytes)
	if err != nil {
		return nil, err
	}

	after, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if changed(before, after, int64(len(data))) {
		return nil, errors.New("input changed during capture")
	}

	return data, nil
}

func readDirectory(ctx context.Context, target string, initial os.FileInfo, limits report.CaptureLimits) (artifact.Snapshot, error) {
	root, err := openCapturedDirectory(target, initial)
	if err != nil {
		return artifact.Snapshot{}, err
	}
	defer func() { _ = root.Close() }()

	b := newBuilder(limits)
	if err := b.walkDirectory(ctx, root); err != nil {
		return b.snapshot("directory"), err
	}

	snapshot := b.snapshot("directory")
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}

	if len(b.files) == 0 && len(b.skipped) == 0 && b.complete {
		return snapshot, errEmpty
	}

	return snapshot, nil
}

func openCapturedDirectory(target string, initial os.FileInfo) (*rootfs.Root, error) {
	root, err := rootfs.Open(target)
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			_ = root.Close()
		}
	}()

	probe, err := root.Open(".")
	if err != nil {
		return nil, err
	}

	actual, statErr := probe.Stat()
	_ = probe.Close()

	if statErr != nil {
		return nil, statErr
	}

	if !os.SameFile(initial, actual) {
		return nil, errors.New("input directory changed before capture")
	}

	success = true

	return root, nil
}

func changed(before, after os.FileInfo, size int64) bool {
	return !os.SameFile(before, after) || before.Size() != after.Size() || after.Size() != size ||
		!before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode()
}

func readBounded(ctx context.Context, r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errors.New("negative read budget")
	}

	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: r}, maxBytes+1))
	if err != nil {
		return data, err
	}

	if int64(len(data)) > maxBytes {
		return data, errors.New("byte budget exceeded")
	}

	if err := ctx.Err(); err != nil {
		return data, err
	}

	return data, nil
}
