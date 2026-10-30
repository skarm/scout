package report

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// EnvironmentReport relates only roots explicitly selected as one environment.
// Observations are review candidates, never proof of activation or data flow.
type EnvironmentReport struct {
	Schema          string                   `json:"schema"`
	Completeness    Completeness             `json:"completeness"`
	MaxObservations int                      `json:"max_observations"`
	MaxOperations   uint64                   `json:"max_operations"`
	Observations    []EnvironmentObservation `json:"observations"`
	Issues          []string                 `json:"issues"`
	Limitations     []string                 `json:"limitations"`
}

// EnvironmentObservation preserves evidence from both sides of a relationship.
// Raw identifiers, URLs, commands and credentials are not included.
type EnvironmentObservation struct {
	ID       string                `json:"id"`
	Kind     string                `json:"kind"`
	Evidence []EnvironmentEvidence `json:"evidence"`
}

// EnvironmentEvidence qualifies file coordinates by their original target.
// Equal relative paths or content hashes in different targets are not aliases.
type EnvironmentEvidence struct {
	TargetID string    `json:"target_id"`
	Role     string    `json:"role"`
	Source   SourceRef `json:"source"`
}

func validateEnvironment(run Run) error {
	e := run.Environment
	if e == nil {
		return nil
	}

	if run.Operation != ScanOperation || e.Schema != "scout.environment-analysis/v1" ||
		!slices.Contains([]Completeness{Complete, Partial}, e.Completeness) ||
		e.MaxObservations < 1 || e.MaxObservations > 4096 || len(e.Observations) > e.MaxObservations || e.MaxOperations > 100000 {
		return errors.New("invalid environment analysis")
	}

	if e.Completeness == Complete && (len(e.Issues) != 0 || e.MaxOperations == 0) ||
		run.State == RunComplete && e.Completeness != Complete {
		return errors.New("complete run requires complete environment analysis")
	}

	files := map[string]File{}

	for _, target := range run.Targets {
		for _, file := range target.Analysis.Artifact.Files {
			files[target.ID+"\x00"+file.Path] = file
		}
	}

	seen := map[string]bool{}
	for _, o := range e.Observations {
		if o.ID == "" || seen[o.ID] {
			return errors.New("invalid environment observation")
		}

		seen[o.ID] = true
		if err := validateEnvironmentObservation(o, files); err != nil {
			return err
		}
	}

	return nil
}

func validateEnvironmentObservation(o EnvironmentObservation, files map[string]File) error {
	a, c := environmentRoles(o.Kind)
	if a == "" || len(o.Evidence) != 2 {
		return errors.New("invalid environment observation kind or evidence count")
	}

	if o.Evidence[0].Role != a || o.Evidence[1].Role != c ||
		o.Evidence[0].TargetID == o.Evidence[1].TargetID && o.Evidence[0].Source.Path == o.Evidence[1].Source.Path {
		return errors.New("invalid environment evidence roles")
	}

	for _, ref := range o.Evidence {
		file, ok := files[ref.TargetID+"\x00"+ref.Source.Path]
		if !ok || file.SHA256 != ref.Source.SHA256 || file.Status != CaptureCaptured ||
			ref.Source.ByteStart < 0 || ref.Source.ByteEnd <= ref.Source.ByteStart || int64(ref.Source.ByteEnd) > file.Size || !environmentSpanHash(ref.Source.SpanSHA256) {
			return errors.New("environment evidence is not bound to a captured target")
		}
	}

	return nil
}

func environmentSpanHash(hash string) bool {
	_, err := hex.DecodeString(hash)
	return len(hash) == 64 && strings.ToLower(hash) == hash && err == nil
}

func environmentRoles(kind string) (string, string) {
	switch kind {
	case "tool_name_collision":
		return "tool_identifier", "tool_identifier"
	case "mcp_name_collision":
		return "mcp_identifier", "mcp_identifier"
	case "capability_combination":
		return "sensitive_read", "network"
	case "skill_reference":
		return "skill_reference", "skill"
	default:
		return "", ""
	}
}
