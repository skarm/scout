// Package knowledge contains trusted, embedded review instructions and rule
// guidance. It never loads policy or prompts from the inspected artifact.
// NVIDIA-derived materials retain Apache-2.0 attribution in NOTICE and sources.
package knowledge

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/skarm/scout/internal/reviewpack"
	"github.com/skarm/scout/report"
)

// Version identifies the knowledge pack's compatibility revision. Inventory's
// SHA256 identifies its exact contents, independently of this label.
const Version = reviewpack.KnowledgeVersion

//go:embed prompts/*.md data/*.json sources/*.md
var content embed.FS

//nolint:gochecknoglobals // Immutable prompt-mode ordering used to build the embedded catalog.
var modes = []string{ModeDiscovery, ModeIntent, ModeQuality, ModeToolConsistency, ModeAssessment, ModeProposalAssessment}

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var catalog = loadCatalog()

//nolint:gochecknoglobals // The bounded manifest describes build-time assets, never scanned input.
var embeddedInventory = sync.OnceValue(buildInventory)

// Reference is the shared report representation of a guidance source.
type Reference = report.GuidanceReference

type (
	// Guide is the shared report representation of rule guidance.
	Guide = report.Guidance
	// PromptDescriptor is the shared report representation of a compiled review
	// prompt.
	PromptDescriptor = report.PromptDescriptor
	// Asset is the shared report representation of an embedded knowledge asset.
	Asset = report.KnowledgeAsset
	// Manifest is the shared report representation of the embedded knowledge
	// inventory.
	Manifest = report.KnowledgeManifest
)

// Modes returns the supported review stages in their stable export order.
// The returned slice cannot change prompt selection or provider routing.
func Modes() []string { return append([]string(nil), modes...) }

// Hash returns the lowercase hexadecimal SHA-256 digest of b.
func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Prompt returns only build-time instructions, never artifact-supplied text.
func Prompt(mode string) (string, error) {
	valid := slices.Contains(modes, mode)
	if !valid {
		return "", errors.New("unsupported review mode")
	}

	base, _ := content.ReadFile("prompts/boundary.md")
	body, _ := content.ReadFile("prompts/" + mode + ".md")
	out := string(base) + "\n" + string(body)
	// Verification must have the original category definitions, not only a name.
	if mode == ModeProposalAssessment {
		b, _ := content.ReadFile("prompts/verification-rubric.md")
		out += "\n" + string(b)
	}

	out += reviewHints(mode)

	return out, nil
}

// Describe returns the digest, byte count and adapted upstream identities for
// a supported review mode.
func Describe(mode string) (PromptDescriptor, error) {
	p, e := Prompt(mode)
	if e != nil {
		return PromptDescriptor{}, e
	}

	ids := map[string][]string{
		ModeDiscovery: {"SSD-1", "SSD-2", "SSD-3", "SSD-4"},
		ModeIntent:    {"SDI-1", "SDI-2", "SDI-3", "SDI-4"},
		ModeQuality:   {"SQP-1", "SQP-2", "SQP-3"},
	}
	ids[ModeToolConsistency] = []string{"TP4"}

	return PromptDescriptor{
		Mode:        mode,
		SHA256:      Hash([]byte(p)),
		Bytes:       len(p),
		UpstreamIDs: append([]string{}, ids[mode]...),
	}, nil
}

// Lookup returns detached compiled guidance and whether id is known.
func Lookup(id string) (Guide, bool) {
	g, ok := catalog[id]
	if !ok {
		return Guide{}, false
	}

	g.ReviewChecks = append([]string{}, g.ReviewChecks...)
	g.BenignConsiderations = append([]string{}, g.BenignConsiderations...)
	g.Sources = append([]Reference{}, g.Sources...)

	return g, true
}

// Catalog returns a detached copy of the complete compiled guidance catalog.
func Catalog() map[string]Guide {
	out := make(map[string]Guide, len(catalog))
	for id := range catalog {
		g, _ := Lookup(id)
		out[id] = g
	}

	return out
}

// Inventory returns a detached manifest of embedded assets and mode-specific
// instructions.
func Inventory() Manifest {
	m := embeddedInventory()
	m.Assets = slices.Clone(m.Assets)

	m.Prompts = slices.Clone(m.Prompts)
	for i := range m.Prompts {
		m.Prompts[i].UpstreamIDs = slices.Clone(m.Prompts[i].UpstreamIDs)
	}

	return m
}

// UpstreamID returns the adapted upstream taxonomy ID for reason, or an empty
// string if none is registered.
func UpstreamID(reason string) string {
	d, _ := LookupReason(reason)
	return d.UpstreamID
}

// ReasonMode returns the required review mode for reason, or an empty string
// when no mode restriction is registered.
func ReasonMode(reason string) string {
	d, _ := LookupReason(reason)
	return d.Mode
}

func buildInventory() Manifest {
	files := 0
	for _, s := range curated.sources {
		files += len(s.Artifacts)
	}

	m := Manifest{
		Version:      Version,
		SourceStatus: fmt.Sprintf("Historical SkillSpector adaptations retain their original provenance in sources/skillspector.md. Additional original Scout review guidance references %d repositories at fixed revisions; %d inspected files have SHA-256 and Git blob identities in data/review_sources.json (2026-10-27). No additional upstream detector code, patterns or prompts imported. Asset digests identify this review pack, not upstream engines or measured detection quality.", len(curated.sources), files),
		Prompts:      []PromptDescriptor{},
		Assets:       []Asset{},
	}

	for _, mode := range modes {
		d, _ := Describe(mode)
		m.Prompts = append(m.Prompts, d)
	}

	for _, dir := range []string{"prompts", "data", "sources"} {
		entries, _ := content.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			p := dir + "/" + e.Name()
			b, _ := content.ReadFile(p)
			m.Assets = append(m.Assets, Asset{Path: p, SHA256: Hash(b), Bytes: len(b)})
		}
	}

	sort.Slice(m.Assets, func(i, j int) bool { return m.Assets[i].Path < m.Assets[j].Path })
	b, _ := json.Marshal(struct {
		Version string
		Assets  []Asset
	}{Version: Version, Assets: m.Assets})
	m.SHA256 = Hash(b)

	return m
}

func loadCatalog() map[string]Guide {
	data, err := content.ReadFile("data/guidance.json")
	if err != nil {
		panic("missing embedded guidance")
	}

	var result map[string]Guide

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&result); err != nil {
		panic("invalid embedded guidance: " + err.Error())
	}

	var languageGuidance map[string]Guide
	readAsset("data/language_guidance.json", &languageGuidance)

	for id, g := range languageGuidance {
		if _, exists := result[id]; exists {
			panic("duplicate language guidance")
		}

		result[id] = g
	}

	for id, g := range result {
		if id == "" || g.Explanation == "" || g.Remediation == "" || len(g.ReviewChecks) == 0 {
			panic("incomplete embedded guidance")
		}
	}

	enrichCatalog(result)

	return result
}
