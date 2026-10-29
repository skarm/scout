package knowledge

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var curated = loadCurated()

// SourceArtifact records inspected upstream bytes, not shipped detector code.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type SourceArtifact struct {
	// Path identifies the inspected file within the pinned reference repository.
	Path string `json:"path"`
	// URL locates the inspected file at its pinned repository revision.
	URL string `json:"url"`
	// SHA256 is the lowercase hexadecimal SHA-256 digest of the referenced bytes.
	SHA256 string `json:"sha256"`
	// GitBlobSHA1 records the inspected file's Git blob identity at the pinned
	// source revision.
	GitBlobSHA1 string `json:"git_blob_sha1"`
	// Bytes is the inspected file's size in bytes.
	Bytes int `json:"bytes"`
}

// ReviewSource records a pinned reference repository, its inspected files and
// the limits of its use.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type ReviewSource struct {
	// ID is the catalog key used by TopicReference.SourceID.
	ID string `json:"id"`
	// Name is the human-readable reference project name.
	Name string `json:"name"`
	// Repository identifies the reference repository from which source artifacts
	// were inspected.
	Repository string `json:"repository"`
	// Revision is the pinned repository commit for the inspected artifacts.
	Revision string `json:"revision"`
	// Retrieved records the source retrieval date preserved in the curated
	// catalog.
	Retrieved string `json:"retrieved"`
	// DeclaredLicense records the reference source's declared license.
	DeclaredLicense string `json:"declared_license"`
	// Use describes how the reference material informs Scout's authored guidance.
	Use string `json:"use"`
	// SelectionReason states why the reference source was selected.
	SelectionReason string `json:"selection_reason"`
	// Limitations states provenance and interpretation limits for this reference
	// source.
	Limitations string `json:"limitations"`
	// Artifacts lists inspected source files and their content identities.
	Artifacts []SourceArtifact `json:"artifacts"`
}

// TopicReference selects an inspected source artifact within a curated
// reference repository.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type TopicReference struct {
	// SourceID selects a curated reference repository by its catalog identity.
	SourceID string `json:"source_id"`
	// Path identifies an inspected file within SourceID.
	Path string `json:"path"`
}

// ReviewExample is an authored contrast scenario, not a detector acceptance test.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type ReviewExample struct {
	// Kind distinguishes the authored risky and benign contrast scenarios.
	Kind string `json:"kind"`
	// Scenario describes an authored review example rather than measured detector
	// behavior.
	Scenario string `json:"scenario"`
}

// ReviewTopic contains review criteria for a concern. RelatedRules links
// guidance, not additional detector coverage.
// Part of the supported Go API for callers outside this repository.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type ReviewTopic struct {
	// ID is the compiled topic key used in knowledge:<topic ID> reasons.
	ID string `json:"id"`
	// Title is the topic's display name.
	Title string `json:"title"`
	// Languages lists the languages to which the review criteria apply.
	Languages []string `json:"languages"`
	// Category is the concern category used for hypotheses about this topic.
	Category string `json:"category"`
	// Coverage is review-guidance-only; topics do not add static detectors.
	Coverage string `json:"coverage"`
	// Modes lists review stages in which this topic's guidance is included.
	Modes []string `json:"modes"`
	// PromptHint contains the compiled topic guidance added to relevant review
	// instructions.
	PromptHint string `json:"prompt_hint"`
	// ReviewChecks lists questions for assessing the concern in its source
	// context.
	ReviewChecks []string `json:"review_checks"`
	// Remediation contains compiled guidance for addressing the concern.
	Remediation string `json:"remediation"`
	// BenignConsiderations lists legitimate contexts to consider without
	// automatically trusting them.
	BenignConsiderations []string `json:"benign_considerations"`
	// Examples contains authored contrast scenarios, not detector acceptance
	// results.
	Examples []ReviewExample `json:"examples"`
	// Sources selects inspected artifacts that inform this authored review topic.
	Sources []TopicReference `json:"sources"`
	// RelatedRules lists rules whose guidance is enriched by the topic without
	// extending their detection semantics.
	RelatedRules []string `json:"related_rules"`
}

type curatedPack struct {
	sources   []ReviewSource
	topics    []ReviewTopic
	artifacts map[TopicReference]SourceArtifact
}

// Pack contains the compiled knowledge manifest, rule guidance, patterns,
// topics and source references.
type Pack struct {
	// Manifest identifies the compiled knowledge assets and instruction
	// descriptors.
	Manifest Manifest `json:"manifest"`
	// Guidance maps compiled rule identities to detached review guidance.
	Guidance map[string]Guide `json:"guidance"`
	// Patterns maps rule identities to detached supplemental expressions.
	Patterns map[string][]Pattern `json:"supplemental_patterns"`
	// Topics contains the authored review lenses in this knowledge export.
	Topics []ReviewTopic `json:"review_topics"`
	// Sources records pinned reference projects and their inspected source
	// artifacts.
	Sources []ReviewSource `json:"review_sources"`
}

// ReviewSources returns detached copies of compiled reference sources and their inspected artifacts.
func ReviewSources() []ReviewSource {
	out := slices.Clone(curated.sources)
	for i := range out {
		out[i].Artifacts = slices.Clone(out[i].Artifacts)
	}

	return out
}

// ReviewTopics returns detached copies of compiled review topics and their
// nested references.
func ReviewTopics() []ReviewTopic {
	out := slices.Clone(curated.topics)
	for i := range out {
		out[i] = cloneTopic(out[i])
	}

	return out
}

// TopicForReason resolves only compiled topic identities. A model can select a
// lens, but cannot supply its guidance, source URLs or an upstream rule identity.
func TopicForReason(reason string) (ReviewTopic, bool) {
	if !strings.HasPrefix(reason, "knowledge:") {
		return ReviewTopic{}, false
	}

	id := strings.TrimPrefix(reason, "knowledge:")
	for _, topic := range curated.topics {
		if topic.ID == id {
			return cloneTopic(topic), true
		}
	}

	return ReviewTopic{}, false
}

// ReviewReasons returns the compiled knowledge topic reasons in catalog order.
func ReviewReasons() []string {
	out := make([]string, 0, len(curated.topics))
	for _, topic := range curated.topics {
		out = append(out, "knowledge:"+topic.ID)
	}

	return out
}

// ReviewTopicIDs returns the topic IDs included in the compiled instructions
// for mode.
func ReviewTopicIDs(mode string) []string {
	out := make([]string, 0)

	for _, topic := range curated.topics {
		if slices.Contains(topic.Modes, mode) {
			out = append(out, topic.ID)
		}
	}

	return out
}

// GuideForReason returns compiled guidance for a topic reason or its adapted
// upstream rule identity.
func GuideForReason(reason string) (Guide, bool) {
	topic, ok := TopicForReason(reason)
	if !ok {
		return Lookup(UpstreamID(reason))
	}

	g := Guide{
		Explanation: topic.PromptHint, Remediation: topic.Remediation,
		ReviewChecks: topic.ReviewChecks, BenignConsiderations: topic.BenignConsiderations, Sources: []Reference{},
	}
	g.Sources = topicReferences(topic)

	return g, true
}

// Export returns a detached snapshot of the manifest, guidance, patterns,
// topics and sources.
func Export() Pack {
	return Pack{
		Manifest: Inventory(),
		Guidance: Catalog(),
		Patterns: PatternCatalog(),
		Topics:   ReviewTopics(),
		Sources:  ReviewSources(),
	}
}

func readAsset(path string, value any) {
	b, err := content.ReadFile(path)
	if err != nil {
		panic("missing knowledge asset: " + path)
	}

	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()

	if err := d.Decode(value); err != nil {
		panic("invalid knowledge asset " + path + ": " + err.Error())
	}

	if err := d.Decode(new(any)); err != io.EOF {
		panic("trailing data in knowledge asset: " + path)
	}
}

func loadCurated() curatedPack {
	var p curatedPack
	readAsset("data/review_sources.json", &p.sources)
	readAsset("data/review_topics.json", &p.topics)

	p.artifacts = sourceArtifacts(p.sources)
	validateTopics(p.topics, p.artifacts)

	return p
}

func cloneTopic(t ReviewTopic) ReviewTopic {
	t.Languages = slices.Clone(t.Languages)
	t.Modes = slices.Clone(t.Modes)
	t.ReviewChecks = slices.Clone(t.ReviewChecks)
	t.BenignConsiderations = slices.Clone(t.BenignConsiderations)
	t.Examples = slices.Clone(t.Examples)
	t.Sources = slices.Clone(t.Sources)
	t.RelatedRules = slices.Clone(t.RelatedRules)

	return t
}

func reviewHints(mode string) string {
	if mode == ModeQuality {
		return ""
	}

	var b strings.Builder
	b.WriteString("\nCURATED REVIEW LENSES — original Scout guidance, not additional static detectors.\n")
	b.WriteString("Use only lenses relevant to the supplied language, evidence and CURRENT MODE. Topic IDs and source references are not excerpt citations. Preserve the mode's proposal/assessment restrictions. Examples in the catalog are authored scenarios, not proof of measured recall.\n")

	if mode == ModeDiscovery {
		b.WriteString("For a concrete security defect covered by a lens, return the exact reason knowledge:<topic ID> (for example knowledge:K-SQL-PARAMS), with scanner-issued citations to the actual unsafe construction/operation and any necessary source or authorization context. This includes code vulnerabilities such as unbound SQL query construction; malicious intent or a purpose mismatch is NOT required. Do not force these into instruction_override or unapproved_execution. A capability, keyword, unused string, safe parameter binding or authorized bounded operation alone is not a defect. No proposal where the necessary evidence is absent. Known attack-semantic reasons remain available for their original meaning.\n")
	} else {
		b.WriteString("knowledge:<topic ID> reasons are discovery-only. In intent/tool_consistency keep the original mismatch definitions; in assessment/proposal_assessment evaluate the supplied hypothesis using its compiled guidance and original evidence. Do not invent new proposals or treat the topic catalog as source evidence.\n")
	}

	for _, t := range curated.topics {
		if slices.Contains(t.Modes, mode) {
			_, _ = fmt.Fprintf(&b, "- %s [%s]: %s\n", t.ID, strings.Join(t.Languages, ","), t.PromptHint)
		}
	}

	return b.String()
}

// enrichCatalog improves explanations for existing rules without changing their
// methods, severities, occurrence identity, coverage or policy.
func enrichCatalog(c map[string]Guide) {
	for _, t := range curated.topics {
		for _, id := range t.RelatedRules {
			g, ok := c[id]
			if !ok {
				panic("unknown related rule for " + t.ID + ": " + id)
			}

			g.ReviewChecks = append(g.ReviewChecks, t.ReviewChecks...)

			g.BenignConsiderations = append(g.BenignConsiderations, t.BenignConsiderations...)
			g.Sources = append(g.Sources, topicReferences(t)...)

			c[id] = g
		}
	}
}

func topicReferences(topic ReviewTopic) []Reference {
	out := make([]Reference, 0, len(topic.Sources))
	for _, ref := range topic.Sources {
		a := curated.artifacts[ref]
		out = append(out, Reference{
			URL:          a.URL,
			Symbol:       topic.ID,
			Relationship: "original Scout review guidance informed by pinned source; not a detector port",
		})
	}

	return out
}

func sourceArtifacts(sources []ReviewSource) map[TopicReference]SourceArtifact {
	out := make(map[TopicReference]SourceArtifact)

	seen := make(map[string]bool)
	for _, s := range sources {
		if slices.Contains([]string{s.ID, s.Repository}, "") || seen[s.ID] || len(s.Revision) != 40 || len(s.Artifacts) == 0 {
			panic("invalid review source: " + s.ID)
		}

		seen[s.ID] = true
		indexSourceArtifacts(out, s)
	}

	return out
}

func indexSourceArtifacts(out map[TopicReference]SourceArtifact, s ReviewSource) {
	for _, a := range s.Artifacts {
		key := TopicReference{SourceID: s.ID, Path: a.Path}

		_, duplicate := out[key]
		if a.Path == "" || duplicate || a.Bytes < 1 || len(a.SHA256) != 64 || len(a.GitBlobSHA1) != 40 {
			panic("invalid review source artifact: " + s.ID)
		}

		out[key] = a
	}
}

func validateTopics(topics []ReviewTopic, artifacts map[TopicReference]SourceArtifact) {
	seen := make(map[string]bool)
	for _, t := range topics {
		if !validTopic(t) || seen[t.ID] {
			panic("invalid review topic: " + t.ID)
		}

		seen[t.ID] = true
		for _, ref := range t.Sources {
			if _, ok := artifacts[ref]; !ok {
				panic("unresolved review topic source: " + t.ID)
			}
		}
	}
}

func validTopic(t ReviewTopic) bool {
	if slices.Contains([]string{t.ID, t.Title, t.Category, t.PromptHint, t.Remediation}, "") ||
		slices.Contains([]int{len(t.Languages), len(t.ReviewChecks), len(t.BenignConsiderations), len(t.Sources)}, 0) || t.Coverage != "review-guidance-only" {
		return false
	}

	for _, mode := range t.Modes {
		if !slices.Contains(modes, mode) || mode == ModeQuality {
			panic("invalid review topic mode: " + t.ID)
		}
	}

	return true
}
