package osv

import (
	"slices"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"golang.org/x/mod/semver"

	"github.com/skarm/scout/report"
)

type affectedRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type snapshotVersion struct {
	sem string
	pep pep440.Version
}

func parseSnapshotVersion(ecosystem, text string) (snapshotVersion, bool) {
	if len(text) > report.MaxAdvisoryCoordinateBytes {
		return snapshotVersion{}, false
	}

	if ecosystem == report.EcosystemPyPI {
		version, err := pep440.Parse(text)
		return snapshotVersion{pep: version}, err == nil
	}

	version := "v" + strings.TrimPrefix(text, "v")

	return snapshotVersion{sem: version}, semver.IsValid(version)
}

func (v snapshotVersion) compare(other snapshotVersion) int {
	if v.sem != "" {
		return semver.Compare(v.sem, other.sem)
	}

	return v.pep.Compare(other.pep)
}

func (a snapshotMatch) matches(ecosystem, raw string, version snapshotVersion) (bool, bool) {
	complete := len(a.versions) != 0 || len(a.ranges) != 0
	for _, text := range a.versions {
		parsed, ok := parseSnapshotVersion(ecosystem, text)
		if raw == text || ok && version.compare(parsed) == 0 {
			return true, true
		}

		complete = complete && ok
	}

	for _, r := range a.ranges {
		if r.Type == "GIT" && (len(a.versions) > 0 || len(a.ranges) > 1) {
			continue // Git ranges supplement a published-version list or range.
		}

		mode, target := ecosystem, version
		if r.Type == "SEMVER" && ecosystem == report.EcosystemPyPI {
			mode = report.EcosystemNPM

			parsed, ok := parseSnapshotVersion(mode, raw)
			if !ok {
				complete = false
				continue
			}

			target = parsed
		}

		hit, supported := r.contains(mode, target)
		if hit {
			return true, true
		}

		complete = complete && supported
	}

	return false, complete
}

type rangeEvent struct {
	version snapshotVersion
	kind    string
	first   bool
}

func (a affectedRange) contains(ecosystem string, target snapshotVersion) (bool, bool) {
	if a.Type != "SEMVER" && a.Type != "ECOSYSTEM" {
		return false, false
	}

	events, outsideLimit, valid := a.timeline(ecosystem, target)
	if !valid || outsideLimit {
		return false, valid
	}

	return affectedByTimeline(events, target), true
}

func (a affectedRange) timeline(ecosystem string, target snapshotVersion) ([]rangeEvent, bool, bool) {
	var events []rangeEvent

	hasLimit, beforeLimit, introduced := false, false, false

	for _, item := range a.Events {
		if len(item) != 1 {
			return nil, false, false
		}

		for kind, version := range item {
			if kind == "limit" && version == "*" {
				hasLimit, beforeLimit = true, true
				continue
			}

			if kind == "introduced" && version == "0" {
				introduced = true

				events = append(events, rangeEvent{kind: kind, first: true})

				continue
			}

			bound, ok := parseSnapshotVersion(ecosystem, version)
			if !ok {
				return nil, false, false
			}

			switch kind {
			case "limit":
				hasLimit, beforeLimit = true, beforeLimit || target.compare(bound) < 0
			case "introduced", "fixed", "last_affected":
				introduced = introduced || kind == "introduced"
				events = append(events, rangeEvent{version: bound, kind: kind})
			default:
				return nil, false, false
			}
		}
	}

	return events, hasLimit && !beforeLimit, introduced
}

func affectedByTimeline(events []rangeEvent, target snapshotVersion) bool {
	slices.SortStableFunc(events, func(a, b rangeEvent) int {
		switch {
		case a.first && !b.first:
			return -1
		case b.first && !a.first:
			return 1
		case a.first:
			return 0
		default:
			return a.version.compare(b.version)
		}
	})

	hit := false

	for _, event := range events {
		// The zero introduction sentinel is earlier than every version.
		if event.first {
			hit = true
			continue
		}

		order := target.compare(event.version)
		switch event.kind {
		case "introduced":
			hit = hit || order >= 0
		case "fixed":
			hit = hit && order < 0
		case "last_affected":
			hit = hit && order <= 0
		}
	}

	return hit
}
