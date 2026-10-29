// Package provenance verifies recorded measurements and their source inventories.
// Hashes prove consistency of recorded bytes, not authenticity of their author.
package provenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/skarm/scout/internal/dev/replaywire"
)

const schema = "scout.provenance/v2"

type file struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type artifact struct {
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	UncompressedSHA256 string `json:"uncompressed_sha256,omitempty"`
}

type summary = replaywire.Summary

type Manifest struct {
	Schema           string         `json:"schema"`
	Version          string         `json:"engine_version"`
	SourceCommit     string         `json:"source_commit"`
	SourceDirty      bool           `json:"source_dirty"`
	ProductSources   []file         `json:"product_sources"`
	DeveloperSources []file         `json:"developer_sources"`
	Input            artifact       `json:"input"`
	Replay           artifact       `json:"replay"`
	SummaryArtifact  artifact       `json:"summary_artifact"`
	Releasecheck     artifact       `json:"releasecheck"`
	Comparison       artifact       `json:"comparison"`
	Summary          summary        `json:"summary"`
	ErrorCounts      map[string]int `json:"error_counts"`
	InputIDsSHA256   string         `json:"sorted_input_ids_sha256"`
}

type Options struct{ Root, Version, Input, Replay, Summary, Releasecheck, Comparison string }

type InputMode string

const (
	InputFile   InputMode = "file"
	inputPinned InputMode = "pinned"
)

// Verification selects capture verification and an optional checkout audit.
// Recorded evidence remains valid when the current checkout changes.
type Verification struct {
	Version        string
	InputMode      InputMode
	InputPin       file
	IDsSHA256      string
	CurrentSources bool
}

// releaseEvidence permits additional measured linkage/build metadata, but its
// required acceptance fields are checked independently of their prose.
type releaseEvidence struct {
	Passed   bool `json:"passed"`
	Selftest struct {
		Passed  bool   `json:"passed"`
		Version string `json:"version"`
	} `json:"selftest"`
}

func Generate(ctx context.Context, options Options) (Manifest, error) {
	root, m, err := sourceManifest(ctx, options)
	if err != nil {
		return Manifest{}, err
	}

	for _, artifact := range []struct {
		target *artifact
		path   string
	}{
		{target: &m.Input, path: options.Input},
		{target: &m.Replay, path: options.Replay},
		{target: &m.SummaryArtifact, path: options.Summary},
		{target: &m.Releasecheck, path: options.Releasecheck},
		{target: &m.Comparison, path: options.Comparison},
	} {
		*artifact.target, err = artifactIdentity(ctx, root, artifact.path)
		if err != nil {
			return Manifest{}, err
		}
	}

	input, err := readInputIDs(ctx, root, m.Input)
	if err != nil {
		return Manifest{}, err
	}

	observed, err := readReplay(ctx, root, m.Replay, m.Version)
	if err != nil {
		return Manifest{}, err
	}

	m.Replay.UncompressedSHA256 = observed.contentSHA256
	if !reflect.DeepEqual(input.ids, observed.ids) {
		return Manifest{}, errors.New("input and replay record IDs differ")
	}

	m.Summary, m.ErrorCounts, m.InputIDsSHA256 = observed.summary, observed.errors, idsDigest(input.ids)
	if err = verifyArtifacts(ctx, root, m, observed, true); err != nil {
		return Manifest{}, err
	}

	return m, nil
}

func Read(root, path string) (Manifest, error) {
	var m Manifest

	data, err := readJSONFile(root, path)
	if err != nil {
		return m, err
	}

	err = decodeStrict(data, &m)

	return m, err
}

func Verify(ctx context.Context, root string, manifest Manifest, expected Verification) error {
	root, err := projectRoot(root)
	if err != nil {
		return err
	}

	if ctx == nil {
		return errors.New("verification context required")
	}

	if err = validateIdentity(manifest, expected); err != nil {
		return err
	}

	if expected.CurrentSources {
		if err := verifySources(ctx, root, manifest); err != nil {
			return err
		}
	}

	observed, err := readReplay(ctx, root, manifest.Replay, manifest.Version)
	if err != nil {
		return err
	}

	if observed.contentSHA256 != manifest.Replay.UncompressedSHA256 {
		return errors.New("replay decoded SHA-256 changed")
	}

	if err = verifyInput(ctx, root, manifest, expected, observed.ids); err != nil {
		return err
	}

	return verifyArtifacts(ctx, root, manifest, observed, expected.CurrentSources)
}

func validateIdentity(m Manifest, expected Verification) error {
	if m.Schema != schema || m.Version == "" || m.Version != expected.Version {
		return errors.New("unsupported provenance identity")
	}

	if !hexDigest(m.SourceCommit, 40) && !hexDigest(m.SourceCommit, 64) {
		return errors.New("invalid source commit")
	}

	if m.Summary.Inputs < 1 || m.Summary.Inputs != m.Summary.Complete+m.Summary.Incomplete+m.Summary.Failed {
		return errors.New("invalid provenance summary")
	}

	if !hexDigest(m.InputIDsSHA256, 64) || !hexDigest(m.Replay.UncompressedSHA256, 64) {
		return errors.New("missing replay identity")
	}

	return validateSourceInventories(m.ProductSources, m.DeveloperSources)
}

func verifyInput(ctx context.Context, root string, m Manifest, expected Verification, ids []string) error {
	switch expected.InputMode {
	case InputFile:
		actual, err := readInputIDs(ctx, root, m.Input)
		if err != nil {
			return err
		}

		if !reflect.DeepEqual(actual.ids, ids) {
			return errors.New("raw input and replay IDs differ")
		}
	case inputPinned:
		if err := verifyPinnedInput(m, expected); err != nil {
			return err
		}
	default:
		return errors.New("explicit file or pinned input verification required")
	}

	if idsDigest(ids) != m.InputIDsSHA256 {
		return errors.New("replay record-ID set changed")
	}

	return nil
}

func verifyArtifacts(ctx context.Context, root string, m Manifest, observed replayEvidence, currentSources bool) error {
	if m.Summary != observed.summary || !reflect.DeepEqual(m.ErrorCounts, observed.errors) {
		return errors.New("replay accounting differs from provenance")
	}

	var summary summary
	if err := readArtifactJSON(ctx, root, m.SummaryArtifact, &summary); err != nil {
		return err
	}

	if summary != observed.summary {
		return errors.New("summary artifact differs from actual replay records")
	}

	var release releaseEvidence
	if err := readArtifactJSON(ctx, root, m.Releasecheck, &release); err != nil {
		return err
	}

	if !release.Passed || !release.Selftest.Passed || release.Selftest.Version != m.Version {
		return errors.New("release acceptance is absent, failed or for another version")
	}

	return verifyComparisonArtifact(ctx, root, m.Comparison, m.Replay, observed, currentSources)
}

func readArtifactJSON(ctx context.Context, root string, artifact artifact, out any) error {
	if err := verifyArtifact(ctx, root, artifact); err != nil {
		return err
	}

	data, err := readJSONFile(root, artifact.Path)
	if err != nil {
		return err
	}
	// Release receipts have a larger independent schema; required fields above
	// are an explicit projection rather than a false claim to validate all of it.
	if _, ok := out.(*releaseEvidence); ok {
		return json.Unmarshal(data, out)
	}

	if err = decodeStrict(data, out); err != nil {
		return fmt.Errorf("%s: %w", artifact.Path, err)
	}

	return nil
}

func sourceManifest(ctx context.Context, options Options) (string, Manifest, error) {
	root, err := projectRoot(options.Root)
	if err != nil {
		return "", Manifest{}, err
	}

	if ctx == nil || options.Version == "" {
		return "", Manifest{}, errors.New("context and engine version required")
	}

	product, developer, err := sourceInventory(ctx, root)
	if err != nil {
		return "", Manifest{}, err
	}

	commit, dirty, err := sourceState(ctx, root)
	if err != nil {
		return "", Manifest{}, err
	}

	m := Manifest{
		Schema:           schema,
		Version:          options.Version,
		SourceCommit:     commit,
		SourceDirty:      dirty,
		ProductSources:   product,
		DeveloperSources: developer,
	}

	return root, m, nil
}

func verifyPinnedInput(m Manifest, expected Verification) error {
	if expected.InputPin.Path == "" || !hexDigest(expected.InputPin.SHA256, 64) || !hexDigest(expected.IDsSHA256, 64) {
		return errors.New("pinned verification requires trusted input and record-ID pins")
	}

	if m.Input.Path != expected.InputPin.Path || m.Input.SHA256 != expected.InputPin.SHA256 || m.InputIDsSHA256 != expected.IDsSHA256 {
		return errors.New("provenance differs from trusted capture pins")
	}

	return nil
}

func verifySources(ctx context.Context, root string, manifest Manifest) error {
	product, developer, err := sourceInventory(ctx, root)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(product, manifest.ProductSources) {
		return errors.New("current product sources differ from the recorded measurement")
	}

	if !reflect.DeepEqual(developer, manifest.DeveloperSources) {
		return errors.New("current developer sources differ from the recorded measurement")
	}

	return nil
}
