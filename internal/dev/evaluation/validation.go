package evaluation

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"unicode"

	"github.com/skarm/scout/internal/capture/archiveutil"
)

const (
	MaxPackageDepth   = 32
	MaxPackageEntries = 8192
)

func (c Corpus) validate() error {
	if !slices.Contains([]int{1, 2}, c.SchemaVersion) || !slices.Contains([]string{"authored_regression_not_holdout", "independent_labelled_corpus"}, c.Kind) || len(c.Cases) == 0 || len(c.Cases) > 4096 {
		return errors.New("invalid corpus identity or case count")
	}

	if c.SchemaVersion == 1 && len(c.Sources) != 0 {
		return errors.New("source metadata requires corpus schema 2")
	}

	if err := c.validateSources(); err != nil {
		return err
	}

	ids := map[string]bool{}
	sources := map[string]string{}
	contents := map[[32]byte]string{}

	for _, value := range c.Cases {
		if ids[value.ID] {
			return errors.New("invalid or duplicate case")
		}

		if err := value.validate(c.SchemaVersion); err != nil {
			return err
		}

		ids[value.ID] = true
		if c.SchemaVersion == 2 {
			if err := value.validateIsolation(c.Sources, sources, contents); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c Corpus) validateSources() error {
	if len(c.Sources) > 4096 || c.SchemaVersion == 2 && len(c.Sources) == 0 {
		return errors.New("schema 2 requires bounded source provenance")
	}

	ids := map[string]bool{}
	for _, source := range c.Sources {
		if !boundedText(source.ID, 128) || ids[source.ID] || !boundedText(source.Origin, 2048) || !boundedText(source.Revision, 256) || !boundedText(source.License, 256) || !boundedText(source.LabelReview, 2048) {
			return errors.New("invalid or duplicate source provenance")
		}

		ids[source.ID] = true
	}

	return nil
}

func (c Case) validate(version int) error {
	if !boundedText(c.ID, 128) || !boundedText(c.Category, 128) {
		return errors.New("invalid case identity")
	}

	if !slices.Contains([]string{"signal", "benign", "ambiguous", "known_static_gap"}, c.Label) {
		return errors.New("invalid case label")
	}

	if version == 1 {
		if !fs.ValidPath(c.Path) || len(c.Path) > 1024 || len(c.Files) != 0 || c.SourceID != "" || c.Split != "" {
			return errors.New("schema 1 requires one reader file without split metadata")
		}

		return nil
	}

	if c.Path != "" || c.Content != "" || len(c.Files) == 0 || len(c.Files) > 1024 || !boundedText(c.SourceID, 128) || !validSplit(c.Split) {
		return errors.New("schema 2 requires package files, source_id and train/tune/holdout split")
	}

	return validateFiles(c.Files)
}

func validSplit(split string) bool {
	return slices.Contains([]string{"train", "tune", "holdout"}, split)
}

func boundedText(text string, limit int) bool {
	return text != "" && text == strings.TrimSpace(text) && len(text) <= limit && !strings.ContainsFunc(text, unicode.IsControl)
}

// Keep the same file namespace on Unix and Windows, including reserved device
// names, alternate streams and case-insensitive directory aliases.
func portablePath(name string) bool {
	if archiveutil.ValidatePath(name, 1024, MaxPackageDepth) != nil || strings.ContainsFunc(name, func(r rune) bool { return r < 32 || r > 126 }) {
		return false
	}

	for part := range strings.SplitSeq(name, "/") {
		if len(part) > 255 {
			return false
		}
	}

	return true
}

func validateFiles(files []File) error {
	namespace := archiveutil.Namespace{MaxNodes: MaxPackageEntries}

	for _, file := range files {
		if !portablePath(file.Path) {
			return errors.New("invalid package file path")
		}

		if err := namespace.Add(file.Path, false); err != nil {
			return errors.New("invalid or over-budget package namespace")
		}
	}

	return nil
}

func (c Case) validateIsolation(provenance []Source, sources map[string]string, contents map[[32]byte]string) error {
	i := slices.IndexFunc(provenance, func(source Source) bool { return source.ID == c.SourceID })
	if i < 0 {
		return errors.New("case references unknown source")
	}

	for _, key := range []string{"id:" + c.SourceID, "origin:" + provenance[i].Origin} {
		if split, ok := sources[key]; ok && split != c.Split {
			return errors.New("source group overlaps corpus splits")
		}

		sources[key] = c.Split
	}

	for _, file := range c.Files {
		if file.Content == "" {
			continue // Empty placeholders do not identify a source.
		}

		hash := sha256.Sum256([]byte(file.Content))
		if split, ok := contents[hash]; ok && split != c.Split {
			return errors.New("identical file content overlaps corpus splits")
		}

		contents[hash] = c.Split
	}

	return nil
}
