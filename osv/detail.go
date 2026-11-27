package osv

import (
	"context"
	"encoding/json"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode"

	cvss20 "github.com/pandatix/go-cvss/20"
	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/report"
)

const (
	maxDetailAliases = 32
	maxDetailSummary = 512
)

type advisoryDetail struct {
	summary  string
	aliases  []string
	severity report.Severity
}

type severityVector struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type severityLabel struct {
	Severity string `json:"severity"`
}

type advisoryRecord struct {
	ID        string             `json:"id"`
	Modified  string             `json:"modified"`
	Withdrawn string             `json:"withdrawn"`
	Summary   string             `json:"summary"`
	Aliases   []string           `json:"aliases"`
	Severity  []severityVector   `json:"severity"`
	Database  severityLabel      `json:"database_specific"`
	Affected  []snapshotAffected `json:"affected"`
}

func (a advisoryRecord) detail(affected []snapshotAffected) *advisoryDetail {
	summary := strings.Join(strings.FieldsFunc(a.Summary, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
	}), " ")

	characters := 0
	for offset := range summary {
		if characters == maxDetailSummary {
			summary = summary[:offset]
			break
		}

		characters++
	}

	out := &advisoryDetail{summary: summary, severity: highestSeverity(a.Severity, a.Database.Severity)}
	for _, alias := range a.Aliases {
		if len(out.aliases) == maxDetailAliases {
			break
		}

		if alias != a.ID && safeID(alias) && !slices.Contains(out.aliases, alias) {
			out.aliases = append(out.aliases, alias)
		}
	}

	slices.Sort(out.aliases)

	for _, item := range affected {
		severity := highestSeverity(item.Severity, item.Database.Severity, item.Ecosystem.Severity)
		if severity.Rank() > out.severity.Rank() {
			out.severity = severity
		}
	}

	return out
}

func highestSeverity(vectors []severityVector, labels ...string) report.Severity {
	var worst report.Severity

	for _, label := range labels {
		severity := report.Severity(strings.ToLower(label))
		if severity == "moderate" {
			severity = report.Medium
		}

		if severity.Rank() > worst.Rank() {
			worst = severity
		}
	}

	for _, vector := range vectors {
		if score, ok := cvssScore(vector); ok {
			severity := severityFromScore(score, vector.Type == "CVSS_V2")
			if severity.Rank() > worst.Rank() {
				worst = severity
			}
		}
	}

	return worst
}

func severityFromScore(score float64, v2 bool) report.Severity {
	switch {
	case score >= 9 && !v2:
		return report.Critical
	case score >= 7:
		return report.High
	case score >= 4:
		return report.Medium
	case score > 0:
		return report.Low
	default:
		return report.Info
	}
}

func cvssScore(v severityVector) (float64, bool) {
	if len(v.Score) > 256 {
		return 0, false
	}

	switch {
	case v.Type == "CVSS_V2":
		parsed, err := cvss20.ParseVector(strings.Trim(strings.TrimPrefix(v.Score, "CVSS:2.0/"), "()"))
		if err == nil {
			return parsed.BaseScore(), true
		}
	case v.Type == "CVSS_V3" && strings.HasPrefix(v.Score, "CVSS:3.0/"):
		parsed, err := cvss30.ParseVector(v.Score)
		if err == nil {
			return parsed.BaseScore(), true
		}
	case v.Type == "CVSS_V3":
		parsed, err := cvss31.ParseVector(v.Score)
		if err == nil {
			return parsed.BaseScore(), true
		}
	case v.Type == "CVSS_V4":
		parsed, err := cvss40.ParseVector(v.Score)
		if err == nil {
			return parsed.Score(), true
		}
	}

	return 0, false
}

func loadOnlineDetails(ctx context.Context, groups []*queryGroup, o Options, requests int) {
	endpoint, err := url.Parse(o.Endpoint)
	if err != nil || path.Base(endpoint.Path) != "querybatch" {
		return
	}

	options := advisoryFetchOptions(o)
	details := map[string]*advisoryRecord{}

	for _, group := range groups {
		for i := range group.ids {
			if ctx.Err() != nil {
				return
			}

			id := &group.ids[i]
			if !id.online {
				continue
			}

			record, seen := details[id.ID]
			if !seen && requests < o.MaxRequests {
				requests++
				record = fetchAdvisoryDetail(ctx, *endpoint, id.ID, options)
				details[id.ID] = record
			}

			if record != nil {
				id.detail = record.detailFor(group.q.Package.Ecosystem, group.q.Package.Name)
			}
		}
	}
}

func fetchAdvisoryDetail(ctx context.Context, address url.URL, id string, options fetch.Options) *advisoryRecord {
	address.Path = path.Join(path.Dir(address.Path), "vulns", id)
	address.RawPath = ""

	body, err := fetch.GetPage(ctx, address.String(), "", options)
	if err != nil {
		return nil
	}

	var decoded advisoryRecord
	if json.Unmarshal(body, &decoded) != nil || decoded.ID != id || decoded.Withdrawn != "" {
		return nil
	}

	return &decoded
}

func (a advisoryRecord) detailFor(ecosystem, name string) *advisoryDetail {
	name = snapshotPackage(ecosystem, name)

	var affected []snapshotAffected

	for _, item := range a.Affected {
		if item.Package.Ecosystem == ecosystem && snapshotPackage(ecosystem, item.Package.Name) == name {
			affected = append(affected, item)
		}
	}

	return a.detail(affected)
}

func advisoryFetchOptions(o Options) fetch.Options {
	base := fetch.DefaultOptions()
	base.Enabled = true
	base.AllowLoopback = o.AllowLoopback
	base.Timeout = o.Timeout
	base.MaxBytes = maxResponse
	base.RootCAs = o.RootCAs

	return base
}
