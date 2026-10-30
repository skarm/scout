// Package baseline applies explicit operator approvals without deleting evidence.
// A baseline is trusted configuration supplied by the caller, never discovered
// in an artifact. It cannot suppress incomplete inspection or model proposals.
package baseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

const (
	// Version is the supported baseline document schema version.
	Version = 1
	// MaxBytes is the maximum accepted baseline JSON size in bytes.
	MaxBytes = 256 << 10
	// MaxEntries is the maximum number of entries in a baseline document.
	MaxEntries = 4096
)

// Shared vocabulary used by this package's protocols and reports.
const (
	valueFingerprint = "fingerprint"
	valueGlob        = "glob"
)

// Entry records a fingerprint or glob approval, its reason and its exclusive expiry time.
type Entry struct {
	Kind string `json:"kind"` // fingerprint or glob
	// Fingerprint selects an exact finding occurrence when Kind is fingerprint.
	Fingerprint string `json:"fingerprint,omitempty"`
	// RuleID selects rules for a glob approval and is unused by fingerprint entries.
	RuleID string `json:"rule_id,omitempty"`
	// PathGlob selects source paths for an explicitly permitted glob approval.
	PathGlob string `json:"path_glob,omitempty"`
	// MessageGlob optionally narrows a glob approval by finding message.
	MessageGlob string `json:"message_glob,omitempty"`
	// Reason is the required operator rationale; reports retain only its digest.
	Reason string `json:"reason"`
	// Expires is the exclusive approval deadline in RFC3339 format.
	Expires string `json:"expires"`
	// Approved distinguishes active approvals from pending entries.
	Approved bool `json:"approved"`
}

// Document is trusted operator configuration bound to an engine, profile and
// optional rulepack digest.
type Document struct {
	// Version is the baseline schema version, which must equal baseline.Version.
	Version int `json:"version"`
	// EngineVersion must match the Scout version recorded in the analysis being approved.
	EngineVersion string `json:"engine_version"`
	// RulepackDigest optionally restricts approvals to the analysis's selected
	// check configuration and rule data.
	RulepackDigest string `json:"rulepack_digest,omitempty"`
	// Profile must match the analysis profile before approvals can apply.
	Profile string `json:"profile"`
	// Entries records approvals in first-match order.
	Entries []Entry `json:"entries"`
}

// Applied is the report representation of an applied operator approval.
type Applied = report.Suppression

// Result summarizes baseline matching without deleting findings from the input
// analysis.
type Result struct {
	// Enabled reports that baseline matching was selected.
	Enabled bool `json:"enabled"`
	// DocumentSHA256 identifies the validated baseline document used for matching.
	DocumentSHA256 string `json:"document_sha256,omitempty"`
	// Status is applied or identity_mismatch, depending on whether the baseline
	// matches the analysis identity.
	Status string `json:"status"`
	// Suppressed records applied operator approvals without removing observations
	// from the run.
	Suppressed []Applied `json:"suppressed"`
	// Expired counts entries whose exclusive expiry has passed.
	Expired int `json:"expired_entries"`
	// Pending counts unexpired entries that have not been approved.
	Pending int `json:"pending_entries"`
	// Unmatched counts eligible entries that did not match a finding, or all
	// entries on an identity mismatch.
	Unmatched int `json:"unmatched_entries"`
}

// Exact approvals have an O(1) lookup. Only earlier eligible glob approvals can
// displace the first exact approval, preserving the document's first-match rule.
type approvalIndex struct {
	exact map[string]int
	globs []int
}

// Parse decodes and validates a bounded baseline document. It rejects
// duplicate keys, unknown fields and trailing JSON.
func Parse(data []byte) (Document, error) {
	var d Document
	if len(data) == 0 || len(data) > MaxBytes {
		return d, errors.New("baseline byte limit")
	}

	root, err := jsonconfig.ParseWithNodeLimit(context.Background(), string(data), len(data))
	if err != nil || !baselineFields(root) {
		return d, errors.New("invalid or ambiguous baseline JSON")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&d); err != nil {
		return Document{}, errors.New("invalid baseline schema")
	}

	if dec.Decode(new(any)) != io.EOF {
		return Document{}, errors.New("trailing baseline data")
	}

	return d, Validate(d)
}

// Exact JSON tags keep the validated approval document independent of the
// case-insensitive struct field matching performed by encoding/json.
func baselineFields(root *jsonconfig.Node) bool {
	if !knownFields(root, "version", "engine_version", "rulepack_digest", "profile", "entries") {
		return false
	}

	if entries := root.Get("entries"); entries != nil {
		for _, entry := range entries.Elements {
			if !knownFields(entry, "kind", "fingerprint", "rule_id", "path_glob", "message_glob", "reason", "expires", "approved") {
				return false
			}
		}
	}

	return true
}

func knownFields(node *jsonconfig.Node, fields ...string) bool {
	if node == nil || node.Kind != jsonconfig.KindObject {
		return false
	}

	for _, member := range node.Members {
		if !slices.Contains(fields, member.Key) {
			return false
		}
	}

	return true
}

// Validate checks the schema, identity fields, entry limits, approval
// selectors and RFC3339 expiry syntax.
func Validate(d Document) error {
	if err := validateHeader(d); err != nil {
		return err
	}

	for _, entry := range d.Entries {
		if err := validateEntry(entry); err != nil {
			return err
		}
	}

	return nil
}

// Fingerprint binds an occurrence and all trace evidence to the exact engine,
// profile and captured file. Even a source edit outside the matched span requires
// reapproval. Equal text in separate occurrences is not collapsed.
func Fingerprint(r report.Analysis, f report.Finding) string {
	payload := struct {
		Version         int
		Engine, Profile string
		Finding         report.Finding
	}{Version: Version, Engine: r.EngineVersion, Profile: r.Profile, Finding: f}

	b, _ := json.Marshal(payload)

	return hash(b)
}

// Create creates one fingerprint entry per finding and validates the result.
// Entries remain pending unless approve is true.
func Create(r report.Analysis, reason string, expires time.Time, approve bool) (Document, error) {
	d := Document{
		Version:        Version,
		EngineVersion:  r.EngineVersion,
		RulepackDigest: r.RulepackDigest,
		Profile:        r.Profile,
		Entries:        []Entry{},
	}
	for _, f := range r.Findings {
		d.Entries = append(d.Entries, Entry{
			Kind:        valueFingerprint,
			Fingerprint: Fingerprint(r, f),
			Reason:      reason,
			Expires:     expires.UTC().Format(time.RFC3339),
			Approved:    approve,
		})
	}

	return d, Validate(d)
}

// Apply always retains the input report. An engine/rulepack/profile mismatch matches no
// entries, and expired/pending entries never exempt a finding. now is trusted.
func Apply(r report.Analysis, d Document, now time.Time, allowGlobs bool) (Result, []report.Finding, error) {
	out := Result{Enabled: true, Status: "applied", Suppressed: []Applied{}}
	if err := Validate(d); err != nil {
		return out, nil, err
	}

	data, _ := json.Marshal(d)
	out.DocumentSHA256 = hash(data)

	active := make([]report.Finding, 0, len(r.Findings))
	if d.EngineVersion != r.EngineVersion || d.Profile != r.Profile || (d.RulepackDigest != "" && d.RulepackDigest != r.RulepackDigest) {
		out.Status = "identity_mismatch"
		out.Unmatched = len(d.Entries)

		return out, append(active, r.Findings...), nil
	}

	if err := validateGlobPermission(d.Entries, allowGlobs); err != nil {
		return out, nil, err
	}

	used := make([]bool, len(d.Entries))
	index := indexApprovals(d.Entries, now, &out)

	for _, f := range r.Findings {
		found := index.find(d.Entries, f, Fingerprint(r, f))
		if found < 0 {
			active = append(active, f)
			continue
		}

		if !used[found] {
			used[found] = true
			out.Unmatched--
		}

		e := d.Entries[found]
		out.Suppressed = append(out.Suppressed, Applied{
			FindingID:    f.ID,
			EntryIndex:   found,
			Kind:         e.Kind,
			ReasonSHA256: hash([]byte(e.Reason)),
			Expires:      e.Expires,
		})
	}

	return out, active, nil
}

// Marshal validates and encodes a bounded, indented baseline document with a
// final newline.
func Marshal(d Document) ([]byte, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}

	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, errors.New("baseline encoding failed")
	}

	if len(b) >= MaxBytes {
		return nil, errors.New("baseline byte limit")
	}

	return append(b, '\n'), nil
}

func validateHeader(d Document) error {
	rulepack, ok := strings.CutPrefix(d.RulepackDigest, "sha256:")
	if d.RulepackDigest != "" && (!ok || !digest(rulepack)) {
		return errors.New("baseline requires a SHA-256 rulepack digest")
	}

	if d.Version != Version || d.EngineVersion == "" || d.Profile == "" || len(d.EngineVersion) > 128 || len(d.Profile) > 256 || d.Entries == nil || len(d.Entries) > MaxEntries {
		return errors.New("invalid baseline header or entry limit")
	}

	return nil
}

func validateEntry(e Entry) error {
	if strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 1024 {
		return errors.New("baseline reason required (1..1024 bytes)")
	}

	if _, err := time.Parse(time.RFC3339, e.Expires); err != nil {
		return errors.New("baseline expiry must be RFC3339")
	}

	switch e.Kind {
	case valueFingerprint:
		return validateFingerprint(e)
	case valueGlob:
		return validateGlob(e)
	default:
		return errors.New("unknown baseline entry kind")
	}
}

func validateFingerprint(e Entry) error {
	if !digest(e.Fingerprint) || e.RuleID != "" || e.PathGlob != "" || e.MessageGlob != "" {
		return errors.New("invalid exact baseline entry")
	}

	return nil
}

func validateGlob(e Entry) error {
	if e.Fingerprint != "" || e.RuleID == "" || e.PathGlob == "" || len(e.RuleID) > 128 || len(e.PathGlob) > 1024 || len(e.MessageGlob) > 1024 {
		return errors.New("glob baseline requires explicit rule and path")
	}

	for _, g := range []string{e.RuleID, e.PathGlob, e.MessageGlob} {
		if _, err := path.Match(g, ""); err != nil {
			return errors.New("invalid baseline glob")
		}
	}

	return nil
}

func validateGlobPermission(entries []Entry, allowed bool) error {
	if allowed {
		return nil
	}

	for _, entry := range entries {
		if entry.Kind == valueGlob {
			return errors.New("glob approvals require explicit permission")
		}
	}

	return nil
}

func indexApprovals(entries []Entry, now time.Time, out *Result) approvalIndex {
	index := approvalIndex{exact: make(map[string]int)}

	for i, e := range entries {
		expiry, _ := time.Parse(time.RFC3339, e.Expires)
		if !now.Before(expiry) {
			out.Expired++
			continue
		}

		if !e.Approved {
			out.Pending++
			continue
		}

		out.Unmatched++

		if e.Kind == valueGlob {
			index.globs = append(index.globs, i)
		} else if _, exists := index.exact[e.Fingerprint]; !exists {
			index.exact[e.Fingerprint] = i
		}
	}

	return index
}

func (index approvalIndex) find(entries []Entry, f report.Finding, fingerprint string) int {
	found, exact := index.exact[fingerprint]
	for _, i := range index.globs {
		if exact && i >= found {
			break
		}

		if matchesGlob(entries[i], f) {
			return i
		}
	}

	if exact {
		return found
	}

	return -1
}

func matchesGlob(e Entry, f report.Finding) bool {
	rule, _ := path.Match(e.RuleID, f.RuleID)
	file, _ := path.Match(e.PathGlob, f.Location.Path)

	message := true
	if e.MessageGlob != "" {
		message, _ = path.Match(e.MessageGlob, f.Message)
	}

	return rule && file && message
}

func digest(s string) bool {
	if len(s) != 64 {
		return false
	}

	_, e := hex.DecodeString(s)

	return e == nil && s == strings.ToLower(s)
}

func hash(b []byte) string {
	x := sha256.Sum256(b)
	return hex.EncodeToString(x[:])
}
