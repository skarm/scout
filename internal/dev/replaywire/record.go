// Package replaywire owns the saved replay contract shared by the producer,
// acceptance verifier and maintenance commands.
package replaywire

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only accepted replay states shared by wire validators.
var replayStates = map[report.State]bool{
	report.RunComplete: true, report.RunIncomplete: false, report.RunFailed: false, report.RunCancelled: false,
}

type Record struct {
	ID            string              `json:"id"`
	Version       string              `json:"version"`
	BudgetSeconds int                 `json:"budget_seconds"`
	Error         string              `json:"error,omitempty"`
	Coverage      report.Completeness `json:"coverage"`
	Decision      report.Decision     `json:"decision"`
	Findings      []report.Finding    `json:"findings"`
	Diagnostics   []string            `json:"diagnostics"`
	State         report.State        `json:"state"`
	RunDigest     string              `json:"run_digest"`
}

type Summary struct {
	Inputs        int `json:"inputs"`
	Complete      int `json:"complete"`
	Incomplete    int `json:"incomplete"`
	Failed        int `json:"failed"`
	Findings      int `json:"findings"`
	RuntimeErrors int `json:"runtime_errors"`
}

// ValidDigest is the lower-case SHA-256 identity grammar used by captured
// records and their saved run bindings.
func ValidDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}

	_, err := hex.DecodeString(value)

	return err == nil
}

func InputRefusal(code string) bool {
	switch code {
	case "unsupported captured path", "input byte limit", "input file count limit":
		return true
	}

	return false
}

func (r Record) Validate(version string) error {
	if err := r.validateIdentity(version); err != nil {
		return err
	}

	if err := r.validateOutcome(); err != nil {
		return err
	}

	if r.Error == "" && (!strings.HasPrefix(r.RunDigest, "sha256:") || !ValidDigest(strings.TrimPrefix(r.RunDigest, "sha256:"))) {
		return errors.New("successful replay row lacks run binding")
	}

	for _, code := range r.Diagnostics {
		if slices.Contains([]string{"analyzer_panic", "analyzer_contract", "invalid_evidence"}, code) {
			return errors.New("replay contains an analyzer runtime/contract fault")
		}
	}

	return nil
}

func (r Record) validateIdentity(version string) error {
	if r.Version == "" || version != "" && r.Version != version {
		return errors.New("replay engine version differs")
	}

	if r.BudgetSeconds < 1 || r.BudgetSeconds > 60 {
		return errors.New("invalid replay case budget")
	}

	if !ValidDigest(r.ID) {
		return errors.New("invalid record ID")
	}

	return nil
}

// Current acceptance and the historical comparison adapter share this wire
// vocabulary; only their state and run-binding requirements differ.
func (r Record) validateVocabulary() error {
	if !slices.Contains([]report.Completeness{report.Complete, report.Partial, report.Failed}, r.Coverage) {
		return errors.New("unknown replay coverage")
	}

	if !slices.Contains([]report.Decision{report.Allow, report.Review, report.Block}, r.Decision) {
		return errors.New("invalid replay decision")
	}

	return nil
}

func (r Record) validateOutcome() error {
	if err := r.validateVocabulary(); err != nil {
		return err
	}

	complete, known := replayStates[r.State]
	if !known {
		return errors.New("unknown replay state")
	}

	if !complete && r.Decision == report.Allow {
		return errors.New("unfinished replay input allowed")
	}

	if complete && (r.Error != "" || r.Coverage != report.Complete) {
		return errors.New("incomplete replay row labeled complete")
	}

	return nil
}

// AddOutcome counts published outcomes. Inputs is tracked separately by the
// stream, which may accept a batch before an output writer fails.
func (s *Summary) AddOutcome(r Record) {
	s.Findings += len(r.Findings)
	if r.Error != "" {
		s.Failed++
		if !InputRefusal(r.Error) {
			s.RuntimeErrors++
		}

		return
	}

	switch r.State {
	case report.RunComplete:
		s.Complete++
	case report.RunIncomplete:
		s.Incomplete++
	default:
		s.Failed++
		s.RuntimeErrors++
	}
}
