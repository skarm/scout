// Package nativecontract defines the release self-test wire contract; it has no native dependencies.
package nativecontract

import (
	"errors"
	"strings"
)

const Schema = "1"

type Check struct {
	ID      string `json:"id"`
	Backend string `json:"backend"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}
type Report struct {
	Schema      string   `json:"schema"`
	Version     string   `json:"version"`
	Platform    string   `json:"platform"`
	Passed      bool     `json:"passed"`
	Checks      []Check  `json:"checks"`
	Limitations []string `json:"limitations"`
}

// IDs is the fixed acceptance plan. Missing engines or checks are failures, not
// skips. This is a smoke/regression gate, not a detection-quality certification.
func IDs() []string {
	return []string{"yaml-values", "yaml-duplicate", "yaml-alias", "toml-values", "toml-duplicate", "python-tree", "python-syntax", "python-flow", "javascript-tree", "javascript-syntax", "javascript-flow", "typescript-tree", "typescript-syntax", "typescript-flow", "sql-tree", "sql-syntax", "sql-flow", "yara-sentinel", "yara-safe", "yara-credentials", "yara-bootstrap", "yara-hidden-instructions", "yara-tool-metadata", "yara-destructive", "yara-invalid", "yara-include", "yara-console"}
}

// Validate also validates a report produced in a clean child process: no omitted,
// repeated, unknown, skipped or unavailable check can yield a passing release.
func Validate(r Report) error {
	if r.Schema != Schema || r.Version == "" || r.Platform == "" {
		return errors.New("invalid selftest identity")
	}

	ids := IDs()
	if len(r.Checks) != len(ids) {
		return errors.New("incomplete selftest plan")
	}

	for i, c := range r.Checks {
		if c.ID != ids[i] || c.Status != "passed" || c.Reason != "" || c.Backend != expectedBackend(c.ID) {
			return errors.New("selftest did not pass")
		}
	}

	return nil
}

func expectedBackend(id string) string {
	p, _, _ := strings.Cut(id, "-")
	if p == "yara" {
		return "yara-x"
	}

	return p
}
