package report

import (
	"crypto/sha256"
	"errors"
)

// RulepackABI identifies the supported additional YARA source contract. Native
// detector code and compiled YARA binaries are not loaded through this contract.
const RulepackABI = "scout.yara-source/v1"

// RulepackIdentity pins the exact operator-selected artifact and its rule source.
// A hash establishes byte identity, not publisher authentication.
type RulepackIdentity struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	ABI         string `json:"abi"`
	SHA256      string `json:"sha256"`
	RulesSHA256 string `json:"rules_sha256"`
}

// Validate checks the supported contract and bounded metadata without loading
// rules, opening files or contacting an update service.
func (p RulepackIdentity) Validate() error {
	if p.ABI != RulepackABI || !advisoryToken(p.ID, 160, "._:/-") || !advisoryToken(p.Version, 64, "._+-") ||
		!rulepackHash(p.SHA256) || !rulepackHash(p.RulesSHA256) {
		return errors.New("invalid rulepack identity or unsupported ABI")
	}

	return nil
}

func rulepackHash(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}

	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}

		return false
	}

	return true
}

func validateRulepack(r SignatureReport) error {
	if r.Rulepack == nil {
		return nil
	}

	if !r.Enabled || !rulepackHash(r.RulesSHA256) {
		return errors.New("selected rulepack requires enabled signature checks and their source hash")
	}

	return r.Rulepack.Validate()
}
