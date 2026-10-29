// Package artifact owns immutable, bounded, in-memory scan inputs.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"path"
	"sort"
	"unicode/utf8"

	"github.com/skarm/scout/report"
)

// File owns immutable captured content and inventory metadata. Its content is
// copied during construction.
type File struct {
	// meta records inventory identity without exposing source contents.
	meta report.File
	// data stores copied source bytes as an immutable string.
	data string
	// generatedName distinguishes scanner-assigned labels from author-supplied
	// filenames without granting trust.
	generatedName bool
}

// NewFile copies data into immutable storage, classifies text versus binary
// and hashes the complete bytes.
func NewFile(name string, data []byte, executable bool) File {
	kind := "text"
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		kind = "binary"
	}

	return File{
		meta: report.File{
			Path: name, Size: int64(len(data)), SHA256: Hash(data),
			Executable: executable, Kind: kind, Status: report.CaptureCaptured,
		},
		data: string(data), // Copy: callers cannot mutate bytes after capture.
	}
}

// Metadata returns value-only metadata without exposing mutable content
// storage.
func (f File) Metadata() report.File { return f.meta }

// Content returns the immutable captured bytes as a string without reopening
// the source.
func (f File) Content() string { return f.data }

// GeneratedName marks scanner-created labels, not author-declared filenames.
// It never disables raw checks or changes the captured bytes/identity.
func (f File) GeneratedName() bool { return f.generatedName }

// WithGeneratedName returns a copy marked with a scanner-generated label
// without changing content or its identity.
func (f File) WithGeneratedName() File { f.generatedName = true; return f }

// Snapshot exposes immutable strings and defensive copies of slices.
type Snapshot struct {
	// files retains captured immutable files in stable path order.
	files []File
	// inventory includes captured and skipped entries for coverage accounting.
	inventory []report.File
	// diagnostics retains capture failures and scope gaps separately from
	// findings.
	diagnostics []report.Diagnostic
	// complete records whether bounded capture completed its selected inventory.
	complete bool
	// kind identifies the acquisition form used for this snapshot.
	kind string
	// digest binds inventory observations without attesting an installation.
	digest string
}

// New copies and sorts captured files, skipped entries and diagnostics, then
// computes the bounded inventory identity.
func New(kind string, files []File, skipped []report.File, diagnostics []report.Diagnostic, complete bool) Snapshot {
	files = append([]File(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].meta.Path < files[j].meta.Path })

	inventory := make([]report.File, 0, len(files)+len(skipped))
	for _, f := range files {
		inventory = append(inventory, f.meta)
	}

	inventory = append(inventory, skipped...)
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })

	diagnostics = append([]report.Diagnostic(nil), diagnostics...)
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].Path != diagnostics[j].Path {
			return diagnostics[i].Path < diagnostics[j].Path
		}

		return diagnostics[i].Code < diagnostics[j].Code
	})

	h := sha256.New()
	writeField(h, "scout-snapshot-v1")

	if complete {
		writeField(h, "complete")
	} else {
		writeField(h, "partial")
	}

	for _, f := range inventory {
		writeField(h, f.Path)
		writeField(h, f.Kind)
		writeField(h, f.Status)
		writeField(h, f.Reason)
		writeField(h, f.SHA256)

		var n [8]byte

		_, _ = binary.Encode(n[:], binary.BigEndian, f.Size)
		h.Write(n[:])

		if f.Executable {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}

	return Snapshot{
		files: files, inventory: inventory, diagnostics: diagnostics,
		complete: complete, kind: kind, digest: hex.EncodeToString(h.Sum(nil)),
	}
}

// Files returns a detached slice of captured files in stable path order.
func (s Snapshot) Files() []File { return append([]File(nil), s.files...) }

// Diagnostics returns an independent copy of capture diagnostics.
func (s Snapshot) Diagnostics() []report.Diagnostic {
	return append([]report.Diagnostic(nil), s.diagnostics...)
}

// Complete reports whether capture finished within the selected inventory
// scope.
func (s Snapshot) Complete() bool { return s.complete }

// Metadata returns detached inventory metadata and discovered skill paths
// without exposing content storage.
func (s Snapshot) Metadata() report.Artifact {
	inventory := append([]report.File{}, s.inventory...)
	skills := make([]string, 0)

	for _, f := range s.files {
		if path.Base(f.meta.Path) == "SKILL.md" {
			skills = append(skills, f.meta.Path)
		}
	}

	return report.Artifact{
		SourceKind: s.kind, SnapshotSHA256: s.digest,
		InventoryComplete: s.complete, IdentityScope: "captured-content-not-install-attestation",
		Files: inventory, Skills: skills,
	}
}

// Hash returns the lowercase hexadecimal SHA-256 digest of data.
func Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func writeField(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	h.Write(length[:])
	h.Write([]byte(value))
}
