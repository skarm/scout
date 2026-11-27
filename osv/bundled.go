package osv

import (
	"context"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/skarm/scout/report"
)

const bundledRevision = "scout-2026-11-27"

type bundledRange struct {
	ecosystem, name, id string
	introduced, end     string // Canonical stable release versions.
	includeEnd          bool
}

// The curated subset projects affected release ranges from the GitHub Advisory
// Database (CC BY 4.0). The advisory IDs resolve to the original records.
func bundledRanges() [7]bundledRange {
	return [7]bundledRange{
		{report.EcosystemNPM, "lodash", "GHSA-35jh-r3h4-6jhm", "", "v4.17.21", false},
		{report.EcosystemNPM, "lodash-es", "GHSA-35jh-r3h4-6jhm", "", "v4.17.21", false},
		{report.EcosystemNPM, "minimist", "GHSA-vh95-rmgr-6w4m", "", "v0.2.1", false},
		{report.EcosystemNPM, "minimist", "GHSA-vh95-rmgr-6w4m", "v1.0.0", "v1.2.3", false},
		{report.EcosystemPyPI, "requests", "GHSA-9wx4-h78v-vm56", "", "v2.32.0", false},
		{report.EcosystemPyPI, "pip", "GHSA-4xh5-x5gv-qwph", "", "v25.2.0", true},
		{report.EcosystemGo, "golang.org/x/net", "GHSA-xrjj-mj9h-534m", "", "v0.4.0", false},
	}
}

func applyBundledFallback(ctx context.Context, groups []*queryGroup, r *report.VulnerabilityReport) {
	for _, g := range groups {
		if ctx.Err() != nil {
			return
		}

		switch r.Queries[g.indices[0]].Status {
		case "not_cached", "provider_failed", "invalid_response", "request_limit", "pagination_loop":
			ids := bundledMatches(g.q.Package.Ecosystem, g.q.Package.Name, g.q.Version)
			if len(ids) != 0 && g.appendResults(ids) {
				setQueryStatus(g, report.OutcomeBundledMatch, r)
			}
		}
	}
}

func bundledMatches(ecosystem, name, version string) []ID {
	version = bundledVersion(ecosystem, version)
	if version == "" {
		return nil
	}

	if ecosystem == report.EcosystemPyPI {
		name = strings.ToLower(name)
	}

	var ids []ID

	for _, advisory := range bundledRanges() {
		if advisory.ecosystem != ecosystem || advisory.name != name ||
			advisory.introduced != "" && semver.Compare(version, advisory.introduced) < 0 {
			continue
		}

		end := semver.Compare(version, advisory.end)
		if end < 0 || end == 0 && advisory.includeEnd {
			ids = append(ids, ID{ID: advisory.id, Source: report.AdvisorySource{
				Name: "GitHub-Advisory-Database", URL: "https://github.com/advisories/" + advisory.id, Revision: bundledRevision,
			}})
		}
	}

	return ids
}

func bundledVersion(ecosystem, version string) string {
	switch ecosystem {
	case report.EcosystemPyPI:
		parts := strings.Split(version, ".")
		if len(parts) > 3 {
			return ""
		}

		for i, part := range parts {
			if part == "" || strings.ContainsFunc(part, func(r rune) bool { return r < '0' || r > '9' }) {
				return ""
			}

			parts[i] = strings.TrimLeft(part, "0")
			if parts[i] == "" {
				parts[i] = "0"
			}
		}

		for len(parts) < 3 {
			parts = append(parts, "0")
		}

		version = "v" + strings.Join(parts, ".")
	case report.EcosystemNPM:
		version = "v" + strings.TrimPrefix(version, "v")
	case report.EcosystemGo:
	default:
		return ""
	}

	if !semver.IsValid(version) || semver.Prerelease(version) != "" || strings.Count(strings.SplitN(version, "+", 2)[0], ".") != 2 {
		return ""
	}

	return version
}
