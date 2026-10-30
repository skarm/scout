// Package environment relates passive facts from explicitly grouped targets.
// It never acquires inputs, executes tools or infers runtime activation.
package environment

import (
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/skarm/scout/internal/analysis/bundle"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

type fact struct {
	bundle.SurfaceFact
	target string
}

type builder struct {
	ctx        context.Context
	out        report.EnvironmentReport
	operations uint64
	seen       map[string]bool
	stopped    bool
}

type factIndex struct {
	identifiers              map[string][]fact
	secrets, networks, links []fact
	skills                   map[string]fact
}

// Build combines source-bound facts without merging the underlying analyses.
// Both work and observation limits are independent of hostile identifier counts.
func Build(ctx context.Context, surfaces []bundle.Surface, targets []report.TargetResult, limit int, operations uint64) report.EnvironmentReport {
	b := builder{ctx: ctx, seen: map[string]bool{}, out: report.EnvironmentReport{
		Schema: "scout.environment-analysis/v1", Completeness: report.Complete,
		MaxObservations: min(limit, 4096), MaxOperations: min(operations, 100000),
		Observations: []report.EnvironmentObservation{}, Issues: []string{},
		Limitations: []string{
			"Only explicitly grouped local roots share this declaration space; ScanMany never groups targets automatically.",
			"Identifiers cover root-level mcpServers/mcp_servers aliases and captured root tools or result.tools arrays. Saved project maps are not merged; server alias collisions and unqualified tool-name collisions are distinct observations. MCP tool schemas are never fetched.",
			"Captured identifiers and capabilities are syntactic candidates, not effective runtime names, permissions, activation or proven cross-component data flow. All cached versions and disabled declarations remain visible.",
			"Capability observers cover selected Go/JS/TS/Python/Shell/SQL syntax. Literal relative Markdown links to captured SKILL.md files are recorded as references, not calls. Archive and other derived-object relationships are outside this environment scope.",
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

	index := factIndex{identifiers: map[string][]fact{}, skills: map[string]fact{}}

	for i, surface := range surfaces {
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

func (b *builder) collect(facts []bundle.SurfaceFact, target string, index *factIndex) bool {
	for _, f := range facts {
		if !b.step() {
			return false
		}

		item := fact{SurfaceFact: f, target: target}
		switch f.Kind {
		case "tool_identifier", "mcp_identifier":
			if !b.identifiers(item, index) {
				return false
			}
		case "sensitive_read":
			index.secrets = append(index.secrets, item)
		case "network":
			index.networks = append(index.networks, item)
		case "skill_reference":
			index.links = append(index.links, item)
		case "skill":
			index.skills[item.target+"\x00"+item.Source.Path] = item
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
			kind := "tool_name_collision"
			if item.Kind == "mcp_identifier" {
				kind = "mcp_name_collision"
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
			b.emit("skill_reference", link, target)
		}
	}

	for _, secret := range index.secrets {
		for _, network := range index.networks {
			if !b.step() {
				return
			}

			if secret.target != network.target || secret.Scope != network.Scope {
				b.emit("capability_combination", secret, network)
			}
		}
	}
}

func (b *builder) result() report.EnvironmentReport {
	sort.Slice(b.out.Observations, func(i, j int) bool { return b.out.Observations[i].ID < b.out.Observations[j].ID })

	if b.ctx.Err() != nil {
		b.issue("cancelled")
	}

	return b.out
}

func (b *builder) step() bool {
	if b.stopped {
		return false
	}

	if b.ctx.Err() != nil {
		b.issue("cancelled")
		return false
	}

	b.operations++
	if b.operations > b.out.MaxOperations {
		b.issue("operation_limit")
		return false
	}

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
	observation := report.EnvironmentObservation{Kind: kind, Evidence: []report.EnvironmentEvidence{
		{TargetID: a.target, Role: a.Kind, Source: a.Source},
		{TargetID: c.target, Role: c.Kind, Source: c.Source},
	}}
	raw, _ := json.Marshal(observation)

	id := artifact.Hash(raw)
	if b.seen[id] {
		return
	}

	if len(b.out.Observations) >= b.out.MaxObservations {
		b.issue("observation_limit")
		b.stopped = true

		return
	}

	b.seen[id] = true
	observation.ID = id
	b.out.Observations = append(b.out.Observations, observation)
}
