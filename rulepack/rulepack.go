// Package rulepack creates and validates bounded, versioned additional YARA
// source artifacts. It performs no filesystem access, downloads or compilation.
package rulepack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	// Schema identifies the strict JSON artifact format.
	Schema = "scout.rulepack/v1"
	// MaxBytes bounds an encoded artifact, including escaped source bytes.
	MaxBytes = jsonconfig.MaxBytes
	// MaxRulesBytes matches the additional-source limit of the signature backend.
	MaxRulesBytes = 256 << 10
)

// Selection contains verified artifact identity and detached UTF-8 source bytes.
// Compilation is performed by the scanner before capturing a target.
type Selection struct {
	Identity report.RulepackIdentity
	Rules    []byte
}

type document struct {
	Schema  string `json:"schema"`
	ID      string `json:"id"`
	Version string `json:"version"`
	ABI     string `json:"abi"`
	YARA    source `json:"yara"`
}

type source struct {
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

// Create builds a deterministic UTF-8 artifact. It checks metadata and byte
// bounds; YARA syntax and backend restrictions are checked when the scanner opens.
func Create(id, version string, rules []byte) ([]byte, error) {
	// Bound caller-owned metadata before the JSON encoder can copy or escape it.
	// The full token/ABI validation remains shared with artifact parsing.
	if len(id) == 0 || len(id) > 160 || len(version) == 0 || len(version) > 64 {
		return nil, errors.New("invalid rulepack metadata size")
	}

	if len(rules) == 0 || len(rules) > MaxRulesBytes || !utf8.Valid(rules) {
		return nil, errors.New("invalid rulepack source encoding or size")
	}

	d := document{Schema: Schema, ID: id, Version: version, ABI: report.RulepackABI, YARA: source{SHA256: hash(rules), Source: string(rules)}}

	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}

	b = append(b, '\n')
	if _, err := Parse(b, ""); err != nil {
		return nil, err
	}

	return b, nil
}

// Parse checks exact JSON fields, compatibility and the embedded source hash.
// expectedSHA256 optionally pins all artifact bytes, including its metadata.
// It is a lowercase 64-digit digest supplied independently by the operator.
func Parse(data []byte, expectedSHA256 string) (Selection, error) {
	if len(data) == 0 || len(data) > MaxBytes {
		return Selection{}, errors.New("invalid rulepack artifact size")
	}

	actual := hash(data)
	if expectedSHA256 != "" && expectedSHA256 != actual {
		return Selection{}, errors.New("rulepack artifact SHA-256 mismatch")
	}

	root, err := jsonconfig.ParseWithNodeLimit(context.Background(), string(data), 32)
	if err != nil || !validShape(root) {
		return Selection{}, errors.New("invalid rulepack JSON shape")
	}

	var d document

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&d) != nil || d.Schema != Schema {
		return Selection{}, errors.New("unsupported rulepack schema")
	}

	info := report.RulepackIdentity{ID: d.ID, Version: d.Version, ABI: d.ABI, SHA256: actual, RulesSHA256: d.YARA.SHA256}
	if err := info.Validate(); err != nil {
		return Selection{}, err
	}

	rules := []byte(d.YARA.Source)
	if len(rules) == 0 || len(rules) > MaxRulesBytes || hash(rules) != info.RulesSHA256 {
		return Selection{}, errors.New("invalid rulepack source size or SHA-256")
	}

	return Selection{Identity: info, Rules: rules}, nil
}

func validShape(n *jsonconfig.Node) bool {
	if n == nil || n.Kind != jsonconfig.KindObject || len(n.Members) != 5 {
		return false
	}

	for _, key := range []string{"schema", "id", "version", "abi"} {
		if _, ok := n.Get(key).Text(); !ok {
			return false
		}
	}

	yara := n.Get("yara")
	if yara == nil || yara.Kind != jsonconfig.KindObject || len(yara.Members) != 2 {
		return false
	}

	for _, key := range []string{"sha256", "source"} {
		if _, ok := yara.Get(key).Text(); !ok {
			return false
		}
	}

	return true
}

func hash(data []byte) string {
	h := sha256.Sum256(data)

	return hex.EncodeToString(h[:])
}
