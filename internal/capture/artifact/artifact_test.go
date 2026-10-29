package artifact_test

import (
	"testing"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestImmutableSnapshot(t *testing.T) {
	data := []byte("original")
	f := artifact.NewFile("a.md", data, false)
	data[0] = 'X'
	files := []artifact.File{f}
	s := artifact.New("directory", files, nil, nil, true)
	files[0] = artifact.NewFile("evil.md", nil, false)
	copyFiles := s.Files()
	copyFiles[0] = artifact.NewFile("evil.md", nil, false)
	meta := s.Metadata()
	meta.Files[0].Path = "changed"
	if s.Files()[0].Content() != "original" || s.Metadata().Files[0].Path != "a.md" {
		t.Fatal("snapshot mutated through caller data")
	}
}

func TestDigest(t *testing.T) {
	a := artifact.NewFile("a.md", []byte("a"), false)
	b := artifact.NewFile("b.md", []byte("b"), false)
	digest := func(files []artifact.File, complete bool) string {
		return artifact.New("directory", files, nil, nil, complete).Metadata().SnapshotSHA256
	}
	if digest([]artifact.File{a, b}, true) != digest([]artifact.File{b, a}, true) {
		t.Fatal("order affects digest")
	}
	if digest([]artifact.File{a}, true) == digest([]artifact.File{a}, false) {
		t.Fatal("scope affects digest but was ignored")
	}
	if digest([]artifact.File{a}, true) == digest([]artifact.File{artifact.NewFile("a.md", []byte("a"), true)}, true) {
		t.Fatal("executable mode missing from digest")
	}
	partial := artifact.New("directory", []artifact.File{a}, []report.File{{Path: "huge", Status: "skipped"}}, nil, false)
	if partial.Metadata().InventoryComplete {
		t.Fatal("false completeness")
	}
}

func TestFileKinds(t *testing.T) {
	for _, tc := range []struct{ name, content, kind string }{{name: "unicode", content: "Привет", kind: "text"}, {
		name:    "nul",
		content: "a\x00b",
		kind:    "binary",
	}, {
		name:    "bad-utf8",
		content: "\xff",
		kind:    "binary",
	}, {
		name:    "empty",
		content: "",
		kind:    "text",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := artifact.NewFile("x", []byte(tc.content), false).Metadata().Kind; got != tc.kind {
				t.Fatalf("%s != %s", got, tc.kind)
			}
		})
	}
}
