package envcompare

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/skarm/scout/report"
)

type environmentRelationshipChange struct {
	Change string                         `json:"change"`
	Kind   string                         `json:"kind"`
	Before *report.EnvironmentObservation `json:"before,omitempty"`
	After  *report.EnvironmentObservation `json:"after,omitempty"`
}

type environmentRelationshipDelta struct {
	Completeness report.Completeness             `json:"completeness"`
	Introduced   int                             `json:"introduced"`
	Persistent   int                             `json:"persistent"`
	NotObserved  int                             `json:"not_observed"`
	Unverified   int                             `json:"unverified"`
	Omitted      int                             `json:"omitted"`
	Changes      []environmentRelationshipChange `json:"changes"`
}

// Observation IDs and target indexes are run-local. Compare evidence under
// stable root IDs. Description overlaps belong to the pair of manifest paths.
func relationshipIndex(doc *report.Document, paths map[string]string) map[string]report.EnvironmentObservation {
	indexed := map[string]report.EnvironmentObservation{}
	if doc == nil || doc.Run.Environment == nil {
		return indexed
	}

	ids := sortedRootIDs(paths, nil)
	targets := map[string]string{}

	for _, t := range doc.Run.Targets {
		if t.Index < len(ids) {
			targets[t.ID] = ids[t.Index]
		}
	}

	counts := map[string]int{}

	for _, observation := range doc.Run.Environment.Observations {
		refs := make([]string, 0, len(observation.Evidence))
		for _, e := range observation.Evidence {
			identity := []string{targets[e.TargetID], e.Role, e.Source.Path}
			if observation.Kind != report.EnvironmentSkillDescriptionOverlap {
				identity = append(identity, e.Source.SpanSHA256)
			}

			data, _ := json.Marshal(identity)
			refs = append(refs, string(data))
		}
		// Roles still bind evidence. Sorting only removes irrelevant pair ordering.
		slices.Sort(refs)
		data, _ := json.Marshal(struct {
			Kind     string
			Evidence []string
		}{observation.Kind, refs})
		key := string(data)
		indexed[fmt.Sprintf("%s/%d", key, counts[key])] = observation
		counts[key]++
	}

	return indexed
}

func environmentComplete(doc *report.Document) bool {
	return doc == nil || doc.Run.State == report.RunComplete && doc.Run.Environment != nil && doc.Run.Environment.Completeness == report.Complete
}

func compareRelationships(before, after *report.Document, old, current map[string]string, limit int) environmentRelationshipDelta {
	delta := environmentRelationshipDelta{Completeness: report.Complete, Changes: []environmentRelationshipChange{}}
	prior, next := relationshipIndex(before, old), relationshipIndex(after, current)

	keys := map[string]string{}
	for key := range prior {
		keys[key] = ""
	}

	for key := range next {
		keys[key] = ""
	}

	if !environmentComplete(before) || !environmentComplete(after) {
		delta.Completeness = report.Partial
	}

	for _, key := range sortedRootIDs(keys, nil) {
		b, bok := prior[key]
		a, aok := next[key]

		change := environmentRelationshipChange{}
		if bok {
			change.Before = &b
			change.Kind = b.Kind
		}

		if aok {
			change.After = &a
			change.Kind = a.Kind
		}

		switch {
		case bok && aok:
			change.Change = "persistent"
			delta.Persistent++
		case aok && environmentComplete(before):
			change.Change = "introduced"
			delta.Introduced++
		case bok && environmentComplete(after):
			change.Change = "not_observed"
			delta.NotObserved++
		default:
			change.Change = "unverified"
			delta.Unverified++
		}

		if len(delta.Changes) >= limit {
			delta.Omitted++
			delta.Completeness = report.Partial

			continue
		}

		delta.Changes = append(delta.Changes, change)
	}

	return delta
}

func relationshipExplanation(kind string) string {
	switch kind {
	case report.EnvironmentCapabilityCombination:
		return "Components expose capabilities that can combine into a sensitive operation; an invocation or data flow is not established."
	case report.EnvironmentMCPNameCollision:
		return "Multiple captured MCP declarations use the same server alias; check which declaration the host selects."
	case report.EnvironmentToolNameCollision:
		return "Multiple captured tools use the same unqualified name; host prefixes and precedence need review."
	case report.EnvironmentSkillReference:
		return "A captured skill links to another skill; the link does not establish invocation or granted authority."
	case report.EnvironmentSkillDescriptionOverlap:
		return "Captured skill descriptions overlap and may compete for the same requests."
	default:
		return "A source-bound relationship between components changed."
	}
}

func relationshipSummary(d environmentRelationshipDelta) string {
	return fmt.Sprintf("Relationships: %d introduced, %d persistent, %d no longer observed, %d unverified; coverage=%s; omitted=%d.", d.Introduced, d.Persistent, d.NotObserved, d.Unverified, d.Completeness, d.Omitted)
}
