package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
)

// ValidateMetadata checks only the optional advisory classification and source.
// Legacy unclassified vulnerability fields retain their existing semantics.
func (v Vulnerability) ValidateMetadata() error {
	if v.Kind != "" && v.Kind != "vulnerability" && v.Kind != AdvisoryMaliciousPackage {
		return errors.New("invalid advisory kind")
	}

	if v.Source != (AdvisorySource{}) && !v.Source.valid() {
		return errors.New("invalid advisory provenance")
	}

	if v.Kind == AdvisoryMaliciousPackage {
		modified, err := time.Parse(time.RFC3339, v.DatabaseModified)
		if err != nil || modified.IsZero() || !v.Source.valid() {
			return errors.New("malicious-package advisory requires provenance and modification time")
		}
	}

	return nil
}

func (s AdvisorySource) valid() bool {
	if !advisoryToken(s.Name, 160, "._:-") || !advisoryToken(s.Revision, 256, "._:+/@-") || len(s.URL) > 2048 {
		return false
	}

	u, err := url.Parse(s.URL)

	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func advisoryToken(s string, limit int, punctuation string) bool {
	if len(s) == 0 || len(s) > limit {
		return false
	}

	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(punctuation, c) {
			continue
		}

		return false
	}

	return true
}

// ValidateMetadata checks advisory classification and provenance, including the
// cached coordinate outcomes required for classified-cache coverage.
// Legacy unclassified query metadata retains its historical semantics.
func (r VulnerabilityReport) ValidateMetadata() error {
	queried, cached, err := validateClassifiedCoverage(r)
	if err != nil {
		return err
	}

	for _, v := range r.Matches {
		if err := v.ValidateMetadata(); err != nil {
			return err
		}

		if v.Kind == AdvisoryMaliciousPackage {
			if !r.Enabled || !r.ClassifiedCache {
				return errors.New("malicious-package advisory requires classified cache coverage")
			}

			modified, _ := time.Parse(time.RFC3339, v.DatabaseModified)
			if modified.After(queried) {
				return errors.New("malicious-package advisory has inconsistent query time")
			}

			if len(v.DependencyIDs) == 0 {
				return errors.New("malicious-package advisory requires a cached coordinate")
			}

			for _, id := range v.DependencyIDs {
				if !cached[id] {
					return errors.New("malicious-package advisory references an uncached coordinate")
				}
			}
		}
	}

	return nil
}

func validateClassifiedCoverage(r VulnerabilityReport) (time.Time, map[string]bool, error) {
	if !r.ClassifiedCache {
		return time.Time{}, nil, nil
	}

	queried, err := time.Parse(time.RFC3339, r.QueriedAt)
	if !r.Enabled || err != nil || queried.IsZero() {
		return time.Time{}, nil, errors.New("classified cache coverage requires an enabled service and query time")
	}

	hash, err := hex.DecodeString(r.DatabaseSHA256)
	if err != nil || len(hash) != sha256.Size {
		return time.Time{}, nil, errors.New("classified cache coverage requires its cache hash")
	}

	cached := map[string]bool{}
	seen := map[string]bool{}

	for _, q := range r.Queries {
		if q.DependencyID == "" || seen[q.DependencyID] || q.Status == OutcomeCompleted || r.Completeness == Complete && q.Status != OutcomeCached {
			return time.Time{}, nil, errors.New("classified cache coverage has inconsistent coordinate outcomes")
		}

		seen[q.DependencyID] = true
		if q.Status == OutcomeCached {
			if q.Ecosystem == "" || q.Name == "" || q.Version == "" || len(q.Name) > 256 || len(q.Version) > 256 {
				return time.Time{}, nil, errors.New("classified cache coverage has an invalid cached coordinate")
			}

			cached[q.DependencyID] = true
		}
	}

	return queried, cached, nil
}

func validateClassifiedInventory(a Analysis) error {
	r := a.Vulnerabilities
	if !r.ClassifiedCache {
		return nil
	}

	if len(r.Queries) != len(a.Dependencies.Declarations) {
		return errors.New("classified cache queries do not cover the dependency inventory")
	}

	declarations := map[string]Dependency{}

	for _, d := range a.Dependencies.Declarations {
		if d.ID == "" || declarations[d.ID].ID != "" {
			return errors.New("classified cache requires unique dependency identities")
		}

		declarations[d.ID] = d
	}

	for _, q := range r.Queries {
		d, ok := declarations[q.DependencyID]
		if !ok || q.Ecosystem != d.Ecosystem || q.Name != d.Module || q.Version != d.DeclaredVersion {
			return errors.New("classified cache query does not match its captured dependency")
		}

		exact := d.VersionSemantics == VersionExactDeclaration || d.VersionSemantics == VersionExactLockfile
		if q.Status == OutcomeCached && !exact {
			return errors.New("classified cache answer requires an exact captured dependency version")
		}
	}

	return nil
}
