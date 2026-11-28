// Package environment relates passive facts from explicitly grouped targets.
// It never acquires inputs, executes tools or infers runtime activation.
package environment

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

type fact struct {
	SurfaceFact
	target string
}

type builder struct {
	ctx        context.Context
	out        report.EnvironmentReport
	operations uint64
	seen       map[string]struct{}
	stopped    bool
	idBuffer   bytes.Buffer
	idEncoder  *json.Encoder
}

type factIndex struct {
	identifiers         map[string][]fact
	capabilities        map[string][]fact
	links               []fact
	skills              map[string]fact
	descriptions        []skillDescription
	unknownDescriptions int
}

// Build combines source-bound facts without merging the underlying analyses.
// Both work and observation limits are independent of hostile identifier counts.
func Build(ctx context.Context, surfaces []Surface, targets []report.TargetResult, limit int, operations uint64) report.EnvironmentReport {
	b := builder{ctx: ctx, seen: map[string]struct{}{}, out: report.EnvironmentReport{
		Schema: "scout.environment-analysis/v1", Completeness: report.Complete,
		MaxObservations: min(limit, report.MaxEnvironmentObservations), MaxOperations: min(operations, report.MaxEnvironmentOperations),
		Observations: []report.EnvironmentObservation{}, Issues: []string{},
		Limitations: []string{
			"Only explicitly grouped local roots share this declaration space; ScanMany never groups targets automatically.",
			"Identifiers cover root-level mcpServers/mcp_servers aliases and captured root tools or result.tools arrays. Saved project maps are not merged; server alias collisions and unqualified tool-name collisions are distinct observations. MCP tool schemas are never fetched.",
			"Captured identifiers and capabilities are syntactic candidates, not effective runtime names, permissions, activation or proven cross-component data flow. All cached versions and disabled declarations remain visible.",
			"Capability observers cover selected Go/JS/TS/Python/Shell/SQL syntax. Literal relative Markdown links to captured SKILL.md files are recorded as references, not calls. Archive and other derived-object relationships are outside this environment scope.",
			"Description overlap compares parsed top-level SKILL.md descriptions using word-set similarity. It indicates possible competition between skills for the same request.",
			"Untrusted-input candidates cover selected HTTP response APIs, Python input and shell read; authenticated responses are not assumed safe. Command/process construction, selected file mutations and literal kubectl/terraform/helm/docker modifying verbs are capabilities, not proof of execution. Request construction alone is not an external-input fact. Python syntax requires the Python check to be enabled and its backend available.",
			"Observations require review, independently of per-target baselines. No source excerpts, raw identifiers or endpoint values are included.",
		},
	}}
	if b.out.MaxOperations == 0 {
		b.issue("operation_limit")
		return b.result()
	}

	if ctx.Err() != nil {
		b.issue("cancelled")
		return b.result()
	}

	index := factIndex{identifiers: map[string][]fact{}, capabilities: map[string][]fact{}, skills: map[string]fact{}}

	for i, surface := range surfaces {
		index.unknownDescriptions += surface.UnknownSkillDescriptions
		if !surface.Complete || targets[i].State != report.RunComplete {
			b.issue("component_context_incomplete")
		}

		if !b.collect(surface.Facts, targets[i].ID, &index) {
			return b.result()
		}
	}

	b.relate(index)

	return b.result()
}

func (b *builder) collect(facts []SurfaceFact, target string, index *factIndex) bool {
	for _, f := range facts {
		if !b.step() {
			return false
		}

		item := fact{SurfaceFact: f, target: target}
		switch f.Kind {
		case report.EnvironmentToolIdentifier, report.EnvironmentMCPIdentifier:
			if !b.identifiers(item, index) {
				return false
			}
		case "sensitive_read", "network", "untrusted_input", "command_execution", "file_write", "infrastructure_mutation":
			index.capabilities[f.Kind] = append(index.capabilities[f.Kind], item)
		case report.EnvironmentSkillReference:
			index.links = append(index.links, item)
		case "skill":
			index.skills[item.target+"\x00"+item.Source.Path] = item
		case report.EnvironmentSkillDescription:
			if words := descriptionWords(item.Value); len(words) != 0 {
				item.Value = ""
				index.descriptions = append(index.descriptions, skillDescription{item, words})
			}
		}
	}

	return true
}

func (b *builder) identifiers(item fact, index *factIndex) bool {
	key := item.Kind + "\x00" + item.Value
	for _, prior := range index.identifiers[key] {
		if !b.step() {
			return false
		}

		if prior.target != item.target || prior.Source.Path != item.Source.Path {
			kind := report.EnvironmentToolNameCollision
			if item.Kind == report.EnvironmentMCPIdentifier {
				kind = report.EnvironmentMCPNameCollision
			}

			b.emit(kind, prior, item)
		}
	}

	index.identifiers[key] = append(index.identifiers[key], item)

	return true
}

func (b *builder) relate(index factIndex) {
	for _, link := range index.links {
		if !b.step() {
			return
		}

		if target, ok := index.skills[link.target+"\x00"+link.Value]; ok {
			b.emit(report.EnvironmentSkillReference, link, target)
		}
	}

	for _, input := range []string{"sensitive_read", "untrusted_input"} {
		for _, effect := range []string{"network", "command_execution", "file_write", "infrastructure_mutation"} {
			if report.EnvironmentCapabilityPair(input, effect) && !b.relateCapabilities(index.capabilities[input], index.capabilities[effect]) {
				return
			}
		}
	}

	b.relateDescriptions(index.descriptions, index.unknownDescriptions)
}

func (b *builder) relateCapabilities(inputs, effects []fact) bool {
	for _, input := range inputs {
		for _, effect := range effects {
			if !b.step() {
				return false
			}

			if input.target != effect.target || input.Scope != effect.Scope {
				b.emit(report.EnvironmentCapabilityCombination, input, effect)
			}
		}
	}

	return true
}

func (b *builder) result() report.EnvironmentReport {
	sort.Slice(b.out.Observations, func(i, j int) bool { return b.out.Observations[i].ID < b.out.Observations[j].ID })

	if b.ctx.Err() != nil {
		b.issue("cancelled")
	}

	return b.out
}

func (b *builder) step() bool {
	return b.spend(1)
}

func (b *builder) spend(operations uint64) bool {
	if b.stopped {
		return false
	}

	if b.ctx.Err() != nil {
		b.issue("cancelled")
		return false
	}

	if operations > b.out.MaxOperations-b.operations {
		b.issue("operation_limit")
		return false
	}

	b.operations += operations

	return true
}

func (b *builder) issue(code string) {
	b.out.Completeness = report.Partial
	if slices.Contains(b.out.Issues, code) {
		return
	}

	b.out.Issues = append(b.out.Issues, code)
}

func (b *builder) emit(kind string, a, c fact) {
	b.emitRelationship(kind, a, c, 0)
}

func (b *builder) emitRelationship(kind string, a, c fact, similarityBasisPoints int) {
	observation := report.EnvironmentObservation{Kind: kind, SimilarityBasisPoints: similarityBasisPoints, Evidence: []report.EnvironmentEvidence{
		{TargetID: a.target, Role: a.Kind, Source: a.Source},
		{TargetID: c.target, Role: c.Kind, Source: c.Source},
	}}

	if b.idEncoder == nil {
		b.idEncoder = json.NewEncoder(&b.idBuffer)
	}

	b.idBuffer.Reset()
	// An observation contains only JSON-supported values. Drop Encode's final
	// newline so the existing observation IDs still hash the same bytes.
	_ = b.idEncoder.Encode(observation)

	id := artifact.Hash(bytes.TrimSuffix(b.idBuffer.Bytes(), []byte{'\n'}))
	if _, seen := b.seen[id]; seen {
		return
	}

	if len(b.out.Observations) >= b.out.MaxObservations {
		b.issue("observation_limit")
		b.stopped = true

		return
	}

	b.seen[id] = struct{}{}
	observation.ID = id
	b.out.Observations = append(b.out.Observations, observation)
}
