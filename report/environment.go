package report

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// EnvironmentAnalysisSchema identifies the environment analysis report format.
const EnvironmentAnalysisSchema = "scout.environment-analysis/v1"

const (
	// MaxEnvironmentObservations limits the number of observations in an environment report.
	MaxEnvironmentObservations = 4096
	// MaxEnvironmentOperations limits the work used to construct an environment report.
	MaxEnvironmentOperations = 100000
)

const (
	EnvironmentCapabilityCombination   = "capability_combination"
	EnvironmentToolNameCollision       = "tool_name_collision"
	EnvironmentMCPNameCollision        = "mcp_name_collision"
	EnvironmentSkillReference          = "skill_reference"
	EnvironmentSkillDescriptionOverlap = "skill_description_overlap"
	EnvironmentSkillDescription        = "skill_description"
	EnvironmentToolIdentifier          = "tool_identifier"
	EnvironmentMCPIdentifier           = "mcp_identifier"
)

const (
	// DescriptionSimilarityScale is the basis-point value for identical word sets.
	DescriptionSimilarityScale  = 10_000
	descriptionOverlapThreshold = DescriptionSimilarityScale / 2
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
	// SimilarityBasisPoints is the Jaccard score scaled to 0–10,000.
	SimilarityBasisPoints int `json:"similarity_basis_points,omitempty"`
}

// EnvironmentEvidence qualifies file coordinates by their original target.
// Equal relative paths or content hashes in different targets are not aliases.
type EnvironmentEvidence struct {
	TargetID string    `json:"target_id"`
	Role     string    `json:"role"`
	Source   SourceRef `json:"source"`
}

type environmentFileKey struct{ target, path string }

func validateEnvironment(run Run) error {
	e := run.Environment
	if e == nil {
		return nil
	}

	if run.Operation != ScanOperation || e.Schema != EnvironmentAnalysisSchema ||
		!slices.Contains([]Completeness{Complete, Partial}, e.Completeness) ||
		e.MaxObservations < 1 || e.MaxObservations > MaxEnvironmentObservations || len(e.Observations) > e.MaxObservations || e.MaxOperations > MaxEnvironmentOperations {
		return errors.New("invalid environment analysis")
	}

	if e.Completeness == Complete && (len(e.Issues) != 0 || e.MaxOperations == 0) ||
		run.State == RunComplete && e.Completeness != Complete {
		return errors.New("complete run requires complete environment analysis")
	}

	files := map[environmentFileKey]File{}

	for _, target := range run.Targets {
		for _, file := range target.Analysis.Artifact.Files {
			files[environmentFileKey{target.ID, file.Path}] = file
		}
	}

	seen := make(map[string]struct{}, len(e.Observations))
	for _, o := range e.Observations {
		if _, duplicate := seen[o.ID]; o.ID == "" || duplicate {
			return errors.New("invalid environment observation")
		}

		seen[o.ID] = struct{}{}
		if err := validateEnvironmentObservation(o, files); err != nil {
			return err
		}
	}

	return nil
}

func validateEnvironmentObservation(o EnvironmentObservation, files map[environmentFileKey]File) error {
	if o.Kind == EnvironmentSkillDescriptionOverlap {
		if o.SimilarityBasisPoints <= descriptionOverlapThreshold || o.SimilarityBasisPoints > DescriptionSimilarityScale {
			return errors.New("invalid skill description similarity")
		}
	} else if o.SimilarityBasisPoints != 0 {
		return errors.New("unexpected environment similarity")
	}

	a, c := environmentRoles(o.Kind)
	if o.Kind == EnvironmentCapabilityCombination && len(o.Evidence) == 2 && EnvironmentCapabilityPair(o.Evidence[0].Role, o.Evidence[1].Role) {
		a, c = o.Evidence[0].Role, o.Evidence[1].Role
	}

	if a == "" || len(o.Evidence) != 2 {
		return errors.New("invalid environment observation kind or evidence count")
	}

	if o.Evidence[0].Role != a || o.Evidence[1].Role != c ||
		o.Evidence[0].TargetID == o.Evidence[1].TargetID && o.Evidence[0].Source.Path == o.Evidence[1].Source.Path {
		return errors.New("invalid environment evidence roles")
	}

	for _, ref := range o.Evidence {
		file, ok := files[environmentFileKey{ref.TargetID, ref.Source.Path}]
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
	case EnvironmentToolNameCollision:
		return EnvironmentToolIdentifier, EnvironmentToolIdentifier
	case EnvironmentMCPNameCollision:
		return EnvironmentMCPIdentifier, EnvironmentMCPIdentifier
	case EnvironmentSkillReference:
		return EnvironmentSkillReference, "skill"
	case EnvironmentSkillDescriptionOverlap:
		return EnvironmentSkillDescription, EnvironmentSkillDescription
	default:
		return "", ""
	}
}

// EnvironmentCapabilityPair defines the ordered capability combinations that
// require review. It does not establish activation or a data flow between them.
func EnvironmentCapabilityPair(input, effect string) bool {
	switch input {
	case CapabilitySensitiveRead:
		return effect == CapabilityNetwork
	case CapabilityUntrustedInput:
		return effect == CapabilityCommandExecution || effect == CapabilityFileWrite || effect == CapabilityInfrastructureMutation
	default:
		return false
	}
}
