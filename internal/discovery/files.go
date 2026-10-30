package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type tree struct {
	b                  *builder
	root               *rootfs.Root
	base, agent, scope string
	plugin, project    string
}

// Only caller-selected roots are canonicalized. Every descendant is opened
// through rootfs, so a manifest cannot redirect reads through a symlink.
func (b *builder) open(base, agent, scope string, required bool, visit func(*tree)) {
	if !b.step(base) {
		return
	}

	absolute, err := filepath.Abs(base)
	if err != nil {
		b.issue("invalid_root", base)
		return
	}

	resolved, err := filepath.EvalSymlinks(absolute)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return
	}

	if err != nil {
		b.issue("root_unreadable", absolute)
		return
	}

	key := agent + ":" + scope + ":" + resolved
	if b.roots[key] {
		return
	}

	b.roots[key] = true

	r, err := rootfs.Open(resolved)
	if err != nil {
		b.issue("root_unreadable", resolved)
		return
	}

	defer func() { _ = r.Close() }()

	visit(&tree{b: b, root: r, base: resolved, agent: agent, scope: scope})
}

func (t *tree) absolute(name string) string { return filepath.Join(t.base, filepath.FromSlash(name)) }

func (t *tree) read(name string, required bool) []byte {
	absolute := t.absolute(name)
	if !t.b.step(absolute) {
		return nil
	}

	f, err := t.root.Open(name)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return nil
	}

	if err != nil {
		t.b.issue("file_unreadable", absolute)
		return nil
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.b.issue("nonregular_refused", absolute)
		return nil
	}

	limit := min(int64(jsonconfig.MaxBytes), t.b.options.MaxBytes-t.b.bytes)
	if info.Size() > limit || limit <= 0 {
		t.b.issue("byte_limit", absolute)
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	t.b.bytes += int64(len(data))

	after, statErr := f.Stat()
	if err != nil || int64(len(data)) > limit || statErr != nil || !os.SameFile(info, after) ||
		info.Size() != int64(len(data)) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		t.b.issue("file_changed_or_unreadable", absolute)
		return nil
	}

	if t.b.ctx.Err() != nil {
		return nil
	}

	hash := sha256.Sum256(data)

	digest := hex.EncodeToString(hash[:])
	if previous, ok := t.b.sources[absolute]; ok {
		if previous != digest {
			t.b.issue("source_changed", absolute)
		}
	} else {
		t.b.sources[absolute] = digest
		t.b.out.Sources = append(t.b.out.Sources, Source{Path: absolute, SHA256: digest})
	}

	t.b.target(absolute)

	return data
}

func (t *tree) entries(name string) []fs.DirEntry {
	if !t.b.step(t.absolute(name)) {
		return nil
	}

	f, err := t.root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		t.b.issue("directory_unreadable", t.absolute(name))
		return nil
	}

	defer func() { _ = f.Close() }()

	entries, err := f.ReadDir(t.b.options.MaxEntries - t.b.entries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		t.b.issue("directory_unreadable", t.absolute(name))
		return nil
	}

	if len(entries) > t.b.options.MaxEntries-t.b.entries {
		t.b.stopped = true
		t.b.issue("entry_limit", t.absolute(name))

		return nil
	}

	t.b.entries += len(entries)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

	return entries
}

func (t *tree) requireDirectory(name string) bool {
	return t.directory(name, true)
}

func (t *tree) directory(name string, required bool) bool {
	if !t.b.step(t.absolute(name)) {
		return false
	}

	f, err := t.root.Open(name)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return false
	}

	if err != nil {
		t.b.issue("referenced_directory_unavailable", t.absolute(name))
		return false
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		t.b.issue("referenced_directory_unavailable", t.absolute(name))
		return false
	}

	return true
}

// walk reports whether the subtree contains files, including a recognized
// component whose visitor intentionally stops recursive discovery.
func (t *tree) walk(name string, depth int, visit func(string) bool) bool {
	if t.b.stopped || t.b.ctx.Err() != nil {
		return false
	}

	if visit(name) {
		return true
	}

	hasFiles := false

	for _, e := range t.entries(name) {
		next := path.Join(name, e.Name())
		switch {
		case e.Type()&os.ModeSymlink != 0:
			t.b.issue("symlink_refused", t.absolute(next))
		case e.IsDir() && !slices.Contains([]string{".git", "node_modules", ".venv", "__pycache__"}, e.Name()):
			if depth >= t.b.options.MaxDepth {
				t.b.issue("depth_limit", t.absolute(next))
			} else if t.walk(next, depth+1, visit) {
				hasFiles = true
			}
		case e.Type().IsRegular():
			hasFiles = true
		}
	}

	return hasFiles
}

func (t *tree) component(kind, name, location, source, key, state string) {
	t.b.add(Component{
		Agent: t.agent, Kind: kind, Name: name, Scope: t.scope,
		Path: t.absolute(location), Source: t.absolute(source), Key: key,
		State: state, Plugin: t.plugin, Project: t.project,
	})
}

func (t *tree) skills(root string) {
	before := len(t.b.out.Components)
	t.walk(root, 0, func(dir string) bool { return t.skill(dir, path.Base(dir)) })

	if len(t.b.out.Components) > before {
		t.b.target(t.absolute(root))
	}
}

func (t *tree) skill(dir, name string) bool {
	manifest := path.Join(dir, "SKILL.md")
	if t.read(manifest, false) == nil {
		return false
	}

	t.component("skill", name, dir, manifest, "", "unknown")

	if t.plugin == "" {
		t.pluginAt(dir)
	}

	return true
}
