package evaluation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"unicode/utf8"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/rootfs"
	"github.com/skarm/scout/internal/textmatch"
)

const MaxCollectionManifestBytes = 256 << 10

type CollectionManifest struct {
	Schema  string           `json:"schema"`
	Kind    string           `json:"kind"`
	Sources []Source         `json:"sources"`
	Cases   []CollectionCase `json:"cases"`
}

type CollectionCase struct {
	ID            string           `json:"id"`
	Category      string           `json:"category"`
	Label         string           `json:"label"`
	SourceID      string           `json:"source_id"`
	Split         string           `json:"split"`
	ExpectedRules []string         `json:"expected_rules"`
	Files         []CollectionFile `json:"files"`
}

type CollectionFile struct {
	Path       string `json:"path"`
	URL        string `json:"url,omitempty"`
	Local      string `json:"local,omitempty"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable,omitempty"`
}

func ParseCollectionManifest(data []byte) (CollectionManifest, error) {
	var manifest CollectionManifest
	if len(data) > MaxCollectionManifestBytes {
		return manifest, errors.New("collection manifest exceeds byte budget")
	}

	if err := validateJSONFields(data, []string{"schema", "kind", "cases", "sources", "id", "category", "label", "path", "url", "local", "sha256", "expected_rules", "files", "source_id", "split", "executable", "origin", "revision", "license", "label_review"}, false); err != nil {
		return manifest, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}

	return manifest, manifest.validate()
}

func (m CollectionManifest) corpus() Corpus {
	corpus := Corpus{SchemaVersion: 2, Kind: m.Kind, Sources: m.Sources, Cases: make([]Case, len(m.Cases))}
	for i, tc := range m.Cases {
		c := Case{ID: tc.ID, Category: tc.Category, Label: tc.Label, SourceID: tc.SourceID, Split: tc.Split, ExpectedRules: tc.ExpectedRules, Files: make([]File, len(tc.Files))}
		for j, file := range tc.Files {
			c.Files[j] = File{Path: file.Path, Executable: file.Executable}
		}

		corpus.Cases[i] = c
	}

	return corpus
}

func (m CollectionManifest) validate() error {
	if m.Schema != "scout.corpus-sources/v1" {
		return errors.New("unsupported collection manifest schema")
	}

	if err := m.corpus().validate(); err != nil {
		return err
	}

	files := 0

	for _, tc := range m.Cases {
		for _, file := range tc.Files {
			files++
			if files > 4096 || !textmatch.LowerHex(file.SHA256, 64) || (file.URL == "") == (file.Local == "") {
				return errors.New("collection requires at most 4096 files, each with one source and a lowercase SHA-256 pin")
			}

			if file.Local != "" && !boundedText(file.Local, 4096) {
				return errors.New("invalid local collection path")
			}

			if file.URL != "" {
				o := fetch.DefaultOptions()

				o.Enabled = true
				if _, err := fetch.ResolveTarget(file.URL, o); err != nil {
					return errors.New("collection requires direct credential-free HTTPS file URLs")
				}
			}
		}
	}

	return nil
}

// Collect verifies every supplied pin before publishing a corpus. No source is
// labelled by scanner output. Unreviewed manifests must retain ambiguous labels
// and cannot pass an evaluation gate. Local paths are relative to base.
func Collect(ctx context.Context, manifest CollectionManifest, base string, download fetch.Options) ([]byte, []string, error) {
	if ctx == nil {
		return nil, nil, errors.New("collection context required")
	}

	if err := manifest.validate(); err != nil {
		return nil, nil, err
	}

	for _, tc := range manifest.Cases {
		for _, file := range tc.Files {
			if file.URL != "" && !download.Enabled {
				return nil, nil, errors.New("external collection requires explicit --allow-download")
			}
		}
	}

	corpus := manifest.corpus()

	var localInputs []string

	remaining := int64(MaxCorpusBytes)

	for i, tc := range manifest.Cases {
		for j, file := range tc.Files {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}

			limit := min(int64(1<<20), remaining)

			data, local, err := collectFile(ctx, file, base, download, limit)
			if err != nil {
				return nil, nil, err
			}

			if !utf8.Valid(data) {
				return nil, nil, errors.New("collection requires UTF-8 text; binary source bytes cannot be preserved in this corpus format")
			}

			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != file.SHA256 {
				return nil, nil, errors.New("collected source SHA-256 does not match its pin")
			}

			corpus.Cases[i].Files[j].Content = string(data)
			remaining -= int64(len(data))

			if local != "" {
				localInputs = append(localInputs, local)
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	data, err := json.MarshalIndent(corpus, "", "  ")

	data = append(data, '\n')
	if err == nil {
		_, err = Parse(data) // Recheck isolation against the actual captured bytes.
	}

	return data, localInputs, err
}

func collectFile(ctx context.Context, file CollectionFile, base string, download fetch.Options, limit int64) ([]byte, string, error) {
	if limit < 1 {
		return nil, "", errors.New("aggregate collection byte budget exhausted")
	}

	if file.URL != "" {
		download.MaxBytes, download.ExpectedSHA256 = min(download.MaxBytes, limit), file.SHA256
		payload, err := fetch.Get(ctx, file.URL, download)

		return payload.Data, "", err
	}

	name := file.Local
	if !filepath.IsAbs(name) {
		name = filepath.Join(base, name)
	}

	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, "", errors.New("invalid local collection path")
	}

	root, err := rootfs.Open(filepath.Dir(absolute))
	if err != nil {
		return nil, "", errors.New("cannot open collection source directory")
	}

	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Base(absolute))
	if err != nil {
		return nil, "", errors.New("cannot open regular collection source")
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, "", errors.New("collection source must be a bounded regular file")
	}

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("collection source exceeds byte budget")
	}

	return data, absolute, err
}
