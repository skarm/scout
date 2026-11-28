// Package envsnapshot captures bounded local environments without executing them.
// Digests detect corruption; they are not signatures or approval decisions.
package envsnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/internal/capture/rootfs"
)

const (
	// Schema identifies the checkpoint content format.
	Schema = "scout.environment-snapshot/v1"
	// MaxBytes bounds a serialized checkpoint including its inspection report.
	MaxBytes   = 48 << 20
	maxContent = 16 << 20
	maxFile    = 4 << 20
	maxEntries = 4096
	maxPath    = 512
	maxDepth   = 32
)

// Root is a caller-named component boundary. Source is display metadata only.
type Root struct {
	// ID is the stable, operator-selected root identifier.
	ID string `json:"id"`
	// Source is the original absolute path; restoration never reads it.
	Source string `json:"source"`
	// Directory distinguishes a directory root from a standalone file.
	Directory bool `json:"directory"`
	// Entries retains files and explicit directories in traversal order.
	Entries []Entry `json:"entries"`
}

// Entry retains exact bytes and executable bits, or an empty directory.
type Entry struct {
	// Path is a portable relative path within the root.
	Path string `json:"path"`
	// Directory marks a directory entry with no bytes or executable bits.
	Directory bool `json:"directory,omitempty"`
	// Executable retains only the original 0111 permission bits.
	Executable uint32 `json:"executable,omitempty"`
	// Data contains exact file bytes, encoded as base64 in JSON.
	Data []byte `json:"data,omitempty"`
	// SHA256 binds Data for regular files.
	SHA256 string `json:"sha256,omitempty"`
}

// Snapshot contains a deterministic content identity, independent of source paths.
type Snapshot struct {
	// Schema must equal the package Schema constant.
	Schema string `json:"schema"`
	// Digest binds Roots excluding display-only Source paths.
	Digest string `json:"digest"`
	// Roots is sorted by stable ID and contains at most 32 roots.
	Roots []Root `json:"roots"`
}

// ValidID accepts portable, unambiguous root identifiers.
func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}

	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}

	return artifactpath.Validate(s, 64, 1) == nil
}

// CaptureError identifies the location and reason for a failed capture.
type CaptureError struct {
	Code   string `json:"code"`
	Root   string `json:"root,omitempty"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"message"`
	Unit   string `json:"unit,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
	Actual int64  `json:"actual,omitempty"`
	cause  error
}

func (e *CaptureError) Error() string {
	location := ""
	if e.Root != "" {
		location = fmt.Sprintf("root %q, path %q: ", e.Root, e.Path)
	}

	if e.Unit != "" {
		return fmt.Sprintf("%s%s (%d %s, maximum %d)", location, e.Detail, e.Actual, e.Unit, e.Limit)
	}

	return location + fmt.Sprintf("%q", e.Detail)
}

func (e *CaptureError) Unwrap() error { return e.cause }

func atPath(code, id, path string, err error) *CaptureError {
	return &CaptureError{Code: code, Root: id, Path: path, Detail: err.Error(), cause: err}
}

func captureLimit(code, detail, id, path, unit string, actual, limit int64) *CaptureError {
	return &CaptureError{Code: code, Root: id, Path: path, Detail: detail, Unit: unit, Actual: actual, Limit: limit}
}

// Capture reads named roots in sorted order. Any skipped or unstable entry fails
// the capture rather than silently creating an apparently complete snapshot.
func Capture(ctx context.Context, inputs map[string]string) (Snapshot, error) {
	s := Snapshot{Schema: Schema, Roots: []Root{}}
	if len(inputs) > 32 {
		return s, captureLimit("root_limit", "too many snapshot roots", "", "", "roots", int64(len(inputs)), 32)
	}

	ids := make([]string, 0, len(inputs))
	for id := range inputs {
		if !ValidID(id) {
			return s, atPath("invalid_root", id, inputs[id], errors.New("invalid root ID"))
		}

		ids = append(ids, id)
	}

	sort.Strings(ids)

	var selected []captureRoot

	count, total := 0, 0

	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return s, atPath("capture_cancelled", id, inputs[id], err)
		}

		source, err := filepath.Abs(inputs[id])
		if err != nil {
			return s, atPath("resolve_root", id, inputs[id], err)
		}

		source, err = filepath.EvalSymlinks(source)
		if err != nil {
			return s, atPath("resolve_root", id, inputs[id], err)
		}

		info, err := os.Stat(source)
		if err != nil {
			return s, atPath("inspect_root", id, source, err)
		}

		if !info.IsDir() && !info.Mode().IsRegular() {
			return s, atPath("nonregular_entry", id, source, errors.New("root must be a regular file or directory"))
		}

		candidate := captureRoot{path: source, info: info}

		overlap, err := candidate.overlaps(ctx, selected)
		if err != nil {
			return s, atPath("inspect_root_boundary", id, source, err)
		}

		if overlap {
			return s, atPath("overlapping_roots", id, source, errors.New("roots overlap or alias"))
		}

		selected = append(selected, candidate)
		r := Root{ID: id, Source: source, Directory: info.IsDir(), Entries: []Entry{}}

		parent, name := filepath.Dir(source), filepath.Base(source)
		if r.Directory {
			parent, name = source, "."
		}

		fs, err := rootfs.Open(parent)
		if err != nil {
			return s, atPath("open_root", id, source, err)
		}

		err = captureEntry(ctx, fs, name, &r, &count, &total)
		closeErr := fs.Close()

		if err != nil {
			return s, err
		}

		if closeErr != nil {
			return s, atPath("close_root", id, source, closeErr)
		}

		s.Roots = append(s.Roots, r)
	}

	s.Digest = identity(s.Roots)
	if err := s.Validate(); err != nil {
		return s, err
	}

	if err := ctx.Err(); err != nil {
		return s, atPath("capture_cancelled", "", "", err)
	}

	return s, nil
}

func captureEntry(ctx context.Context, fs *rootfs.Root, name string, r *Root, count, total *int) error {
	path := r.entryPath(name)
	if err := ctx.Err(); err != nil {
		return atPath("capture_cancelled", r.ID, path, err)
	}

	*count++
	if *count > maxEntries {
		return captureLimit("entry_limit", "snapshot entry limit exceeded", r.ID, path, "entries", int64(*count), maxEntries)
	}

	if name != "." {
		if err := validateCapturePath(r.ID, path, name); err != nil {
			return err
		}
	}

	f, err := fs.Open(name)
	if err != nil {
		return atPath("open_entry", r.ID, path, err)
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return atPath("inspect_entry", r.ID, path, err)
	}

	if info.IsDir() {
		return captureDirectory(ctx, fs, f, info, name, r, count, total)
	}

	return captureFile(f, info, name, r, total)
}

func (r Root) entryPath(name string) string {
	if !r.Directory {
		return r.Source
	}

	return filepath.Join(r.Source, filepath.FromSlash(name))
}

func validateCapturePath(id, path, name string) error {
	if len(name) > maxPath {
		return captureLimit("path_size_limit", "snapshot path too long", id, path, "bytes", int64(len(name)), maxPath)
	}

	depth := strings.Count(name, "/") + 1
	if depth > maxDepth {
		return captureLimit("path_depth_limit", "snapshot path too deep", id, path, "components", int64(depth), maxDepth)
	}

	if err := artifactpath.Validate(name, maxPath, maxDepth); err != nil {
		return atPath("invalid_entry_path", id, path, err)
	}

	return nil
}

func captureFile(f *os.File, info os.FileInfo, name string, r *Root, total *int) error {
	path := r.entryPath(name)
	if !info.Mode().IsRegular() {
		return atPath("nonregular_entry", r.ID, path, errors.New("expected a regular file"))
	}

	checkSize := func(size int64) error {
		if size > maxFile {
			return captureLimit("file_size_limit", "snapshot file too large", r.ID, path, "bytes", size, maxFile)
		}

		if size > int64(maxContent-*total) {
			return captureLimit("content_size_limit", "total snapshot content too large", r.ID, path, "bytes", size+int64(*total), maxContent)
		}

		return nil
	}
	if err := checkSize(info.Size()); err != nil {
		return err
	}

	data, err := io.ReadAll(io.LimitReader(f, int64(min(maxFile, maxContent-*total))+1))
	if err != nil {
		return atPath("read_file", r.ID, path, err)
	}

	if err := checkSize(int64(len(data))); err != nil {
		return err
	}

	after, err := f.Stat()
	if err != nil {
		return atPath("inspect_entry", r.ID, path, err)
	}

	if int64(len(data)) != info.Size() || after.Size() != info.Size() || !info.ModTime().Equal(after.ModTime()) || info.Mode() != after.Mode() {
		return atPath("file_changed", r.ID, path, errors.New("file changed during snapshot"))
	}

	*total += len(data)
	r.Entries = append(r.Entries, Entry{Path: name, Data: data, Executable: uint32(info.Mode().Perm() & 0o111), SHA256: hash(data)})

	return nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func identity(roots []Root) string {
	copyRoots := append([]Root(nil), roots...)
	for i := range copyRoots {
		copyRoots[i].Source = ""
	}

	data, _ := json.Marshal(copyRoots)

	return hash(data)
}

// Validate rejects corrupt content, unsafe paths and namespace collisions before
// any files are materialized. Source paths are never followed when restoring.
func (s Snapshot) Validate() error {
	if s.Schema != Schema || len(s.Roots) > 32 || s.Digest != identity(s.Roots) {
		return errors.New("invalid snapshot identity or schema")
	}

	count, total := 0, 0

	previous := ""
	for _, r := range s.Roots {
		if !ValidID(r.ID) || r.ID <= previous || len(r.Source) > 4096 {
			return errors.New("invalid or duplicate snapshot root")
		}

		previous = r.ID
		if r.Directory {
			count++
		}

		if count > maxEntries {
			return errors.New("snapshot entry limit exceeded")
		}

		if !r.Directory && (len(r.Entries) != 1 || r.Entries[0].Directory || strings.Contains(r.Entries[0].Path, "/")) {
			return errors.New("invalid standalone root")
		}

		if err := validateEntries(r, &count, &total); err != nil {
			return err
		}
	}

	return nil
}

// Materialize writes validated bytes into a caller-owned private empty directory.
// Returned paths retain the original file/directory boundaries for analysis.
func (s Snapshot) Materialize(ctx context.Context, directory string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}

	paths := map[string]string{}

	for _, r := range s.Roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		base := filepath.Join(directory, r.ID)
		if err := os.Mkdir(base, 0o700); err != nil {
			return nil, err
		}

		paths[r.ID] = base

		path, err := restoreRoot(ctx, r, base)
		if err != nil {
			return nil, err
		}

		paths[r.ID] = path
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

type captureRoot struct {
	path string
	info os.FileInfo
}

func (r captureRoot) overlaps(ctx context.Context, previous []captureRoot) (bool, error) {
	for _, other := range previous {
		if os.SameFile(r.info, other.info) {
			return true, nil
		}

		if inside, err := other.contains(ctx, r.path); inside || err != nil {
			return inside, err
		}

		if inside, err := r.contains(ctx, other.path); inside || err != nil {
			return inside, err
		}
	}

	return false, nil
}

func (r captureRoot) contains(ctx context.Context, path string) (bool, error) {
	if !r.info.IsDir() {
		return false, nil
	}

	// Directory identity also detects aliases on case-insensitive volumes.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		info, err := os.Stat(parent)
		if err != nil {
			return false, err
		}

		if os.SameFile(r.info, info) {
			return true, nil
		}

		if filepath.Dir(parent) == parent {
			return false, nil
		}
	}
}

func captureDirectory(ctx context.Context, fs *rootfs.Root, f *os.File, info os.FileInfo, name string, r *Root, count, total *int) error {
	if name != "." {
		r.Entries = append(r.Entries, Entry{Path: name, Directory: true})
	}

	children, err := f.ReadDir(maxEntries - *count + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return atPath("read_directory", r.ID, r.entryPath(name), err)
	}

	if len(children) > maxEntries-*count {
		return captureLimit("entry_limit", "snapshot entry limit exceeded", r.ID, r.entryPath(name), "entries", int64(*count+len(children)), maxEntries)
	}

	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })

	for _, child := range children {
		next := child.Name()
		if name != "." {
			next = name + "/" + next
		}

		if child.Type()&os.ModeSymlink != 0 {
			return atPath("symbolic_link", r.ID, r.entryPath(next), errors.New("nested symbolic link is not supported"))
		}

		if err := captureEntry(ctx, fs, next, r, count, total); err != nil {
			return err
		}
	}

	after, err := f.Stat()
	if err != nil {
		return atPath("inspect_entry", r.ID, r.entryPath(name), err)
	}

	if !info.ModTime().Equal(after.ModTime()) {
		return atPath("directory_changed", r.ID, r.entryPath(name), errors.New("directory changed during snapshot"))
	}

	return nil
}

func validateEntries(r Root, count, total *int) error {
	names := map[string]bool{}
	namespace := artifactpath.Namespace{MaxNodes: maxEntries}

	for _, e := range r.Entries {
		*count++

		*total += len(e.Data)
		if *count > maxEntries || *total > maxContent || len(e.Data) > maxFile || artifactpath.Validate(e.Path, maxPath, maxDepth) != nil {
			return errors.New("invalid snapshot entry or limit")
		}

		if err := namespace.Add(e.Path, e.Directory); err != nil {
			return atPath("entry_namespace", r.ID, r.entryPath(e.Path), err)
		}

		key := e.Path
		if _, ok := names[key]; ok {
			return errors.New("duplicate snapshot path")
		}

		for parent := filepath.ToSlash(filepath.Dir(key)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			if dir, ok := names[parent]; !ok || !dir {
				return errors.New("missing directory or conflicting snapshot path")
			}
		}

		names[key] = e.Directory
		if e.Executable & ^uint32(0o111) != 0 {
			return errors.New("invalid executable bits")
		}

		if e.Directory {
			if len(e.Data) != 0 || e.SHA256 != "" || e.Executable != 0 {
				return errors.New("invalid directory entry")
			}
		} else if hash(e.Data) != e.SHA256 {
			return errors.New("snapshot content checksum mismatch")
		}
	}

	return nil
}

func restoreRoot(ctx context.Context, r Root, base string) (string, error) {
	rootPath := base

	for _, e := range r.Entries {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		name := filepath.Join(base, filepath.FromSlash(e.Path))
		if e.Directory {
			if err := os.Mkdir(name, 0o700); err != nil {
				return "", err
			}

			continue
		}

		if err := restoreFile(name, e); err != nil {
			return "", err
		}

		if !r.Directory {
			rootPath = name
		}
	}

	return rootPath, nil
}

func restoreFile(name string, entry Entry) error {
	//nolint:gosec // The path was validated and is inside a new private directory.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(entry.Data)
	if writeErr == nil && entry.Executable != 0 {
		// Chmod applies the recorded executable bits independently of umask.
		writeErr = f.Chmod(0o600 | os.FileMode(entry.Executable))
	}

	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}

	info, err := os.Stat(name)
	if err != nil {
		return err
	}

	if uint32(info.Mode().Perm()&0o111) != entry.Executable {
		return fmt.Errorf("cannot preserve snapshot executable bits: %q", entry.Path)
	}

	return nil
}

// Root looks up a root in a validated or freshly captured snapshot.
func (s Snapshot) Root(id string) Root {
	i, ok := slices.BinarySearchFunc(s.Roots, id, func(root Root, id string) int {
		return strings.Compare(root.ID, id)
	})
	if !ok {
		return Root{}
	}

	return s.Roots[i]
}

// ContentDigest binds a validated root's ordered inventory and file digests.
// The file digests already bind the bytes, so comparison does not re-encode them.
func (r Root) ContentDigest() string {
	r.Entries = slices.Clone(r.Entries)
	for i := range r.Entries {
		r.Entries[i].Data = nil
	}

	return identity([]Root{r})
}
