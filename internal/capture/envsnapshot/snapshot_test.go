package envsnapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/skarm/scout/internal/capture/envsnapshot"
)

func TestCaptureRestoreAndIdentity(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "plugin")
	if err := os.MkdirAll(filepath.Join(input, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 255, 10, 1}
	sourceFile := filepath.Join(input, "payload.bin")
	if err := os.WriteFile(sourceFile, data, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := envsnapshot.Capture(context.Background(), map[string]string{"plugin": input})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded envsnapshot.Snapshot
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	restored, err := decoded.Materialize(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if empty, err := os.ReadDir(filepath.Join(restored["plugin"], "empty")); err != nil || len(empty) != 0 {
		t.Fatalf("restored empty directory contains %v, error %v; want an empty directory", empty, err)
	}
	actual, err := os.ReadFile(filepath.Join(restored["plugin"], "payload.bin"))
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("binary changed", err)
	}
	again, err := envsnapshot.Capture(context.Background(), restored)
	if err != nil || again.Digest != s.Digest {
		t.Fatal("identity depends on source location", err)
	}
	t.Run("executable identity", func(t *testing.T) {
		original, err := os.Stat(sourceFile)
		if err != nil {
			t.Fatal(err)
		}
		if original.Mode().Perm()&0o111 == 0 {
			t.Skip("source filesystem does not expose Unix executable bits")
		}
		file := filepath.Join(restored["plugin"], "payload.bin")
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("restored file mode %v lost source executable bits", info.Mode())
		}
		if err := os.Chmod(file, 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := envsnapshot.Capture(t.Context(), restored)
		if err != nil || changed.Digest == s.Digest {
			t.Fatal("executable bits not bound", err)
		}
	})
	decoded.Roots[0].Entries[len(decoded.Roots[0].Entries)-1].Data = []byte("tampered")
	if _, err = decoded.Materialize(context.Background(), t.TempDir()); err == nil {
		t.Fatal("restored corrupt content")
	}
}

func TestRootSameContentPreservesOrderedInventory(t *testing.T) {
	original := envsnapshot.Root{ID: "main", Source: "/previous", Directory: true, Entries: []envsnapshot.Entry{
		{Path: "nested", Directory: true},
		{Path: "notes.txt", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}}
	for _, tc := range []struct {
		name string
		edit func(*envsnapshot.Root)
		same bool
	}{
		{name: "source", edit: func(root *envsnapshot.Root) { root.Source = "/candidate" }, same: true},
		{name: "entry order", edit: func(root *envsnapshot.Root) { slices.Reverse(root.Entries) }},
		{name: "entry kind", edit: func(root *envsnapshot.Root) { root.Entries[0].Directory = false }},
		{name: "file digest", edit: func(root *envsnapshot.Root) { root.Entries[1].SHA256 = "changed" }},
		{name: "executable bits", edit: func(root *envsnapshot.Root) { root.Entries[1].Executable = 0o111 }},
		{name: "path", edit: func(root *envsnapshot.Root) { root.Entries[1].Path = "other.txt" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := original
			other.Entries = slices.Clone(original.Entries)
			tc.edit(&other)
			if got := original.SameContent(other); got != tc.same {
				t.Fatalf("SameContent = %v, want %v", got, tc.same)
			}
		})
	}
}

func TestRootSameContentDistinguishesEmptyInventoryRepresentations(t *testing.T) {
	empty := envsnapshot.Root{ID: "main", Directory: true, Entries: []envsnapshot.Entry{}}
	null := envsnapshot.Root{ID: "main", Directory: true}
	if !empty.SameContent(empty) || !null.SameContent(null) || empty.SameContent(null) || null.SameContent(empty) {
		t.Fatal("the checkpoint's null and empty inventory identities changed")
	}
}

func TestCaptureRejectsLinksOverlapAndLimits(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := envsnapshot.Capture(context.Background(), map[string]string{"a": base, "b": filepath.Join(base, "sub")}); err == nil {
		t.Fatal("overlapping roots accepted")
	}
	t.Run("nested symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
			t.Skip("symlinks unavailable: ", err)
		}
		if _, err := envsnapshot.Capture(t.Context(), map[string]string{"main": root}); err == nil {
			t.Fatal("followed link")
		}
	})
	if err := os.WriteFile(filepath.Join(base, "big"), make([]byte, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := envsnapshot.Capture(context.Background(), map[string]string{"main": base}); err == nil {
		t.Fatal("file limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := envsnapshot.Capture(ctx, map[string]string{"main": base}); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestCancelledSnapshotOperationsDoNotStart(t *testing.T) {
	t.Run("empty capture", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := envsnapshot.Capture(ctx, nil)
		var problem *envsnapshot.CaptureError
		if !errors.Is(err, context.Canceled) || !errors.As(err, &problem) || problem.Code != "capture_cancelled" {
			t.Fatalf("empty capture lost cancellation: %v", err)
		}
	})
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty root", true: "populated root"}[populated], func(t *testing.T) {
			input, output := t.TempDir(), t.TempDir()
			if populated {
				if err := os.WriteFile(filepath.Join(input, "note.txt"), []byte("ordinary text"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := envsnapshot.Capture(t.Context(), map[string]string{"main": input})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if paths, err := s.Materialize(ctx, output); !errors.Is(err, context.Canceled) || paths != nil {
				t.Errorf("materialization lost cancellation: paths=%v error=%v", paths, err)
			}
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cancelled materialization changed the workspace: entries=%v error=%v", entries, err)
			}
		})
	}
}

func TestCaptureRejectsCaseAliasOfAncestor(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "parent")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "PARENT", "nested")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("case-sensitive temporary volume")
	} else if err != nil {
		t.Fatal(err)
	}

	for _, roots := range []map[string]string{
		{"a": root, "b": alias},
		{"a": alias, "b": root},
	} {
		_, err := envsnapshot.Capture(t.Context(), roots)
		var problem *envsnapshot.CaptureError
		if !errors.As(err, &problem) || problem.Code != "overlapping_roots" {
			t.Fatal("overlap through an aliased ancestor was not rejected", err)
		}
	}
}
