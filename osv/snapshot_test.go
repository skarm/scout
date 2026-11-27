package osv_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
)

func TestSnapshotChecksEcosystemVersionsAndCoverage(t *testing.T) {
	archives := map[string]osv.SnapshotArchive{
		report.EcosystemGo:   snapshotZIP(t, "GO-test", `{"id":"GO-test","summary":"Go advisory","aliases":["CVE-test"],"database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"Go","name":"example.org/lib"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.0"},{"introduced":"1.0.0"}]}]}]}`),
		report.EcosystemNPM:  snapshotZIP(t, "NPM-test", `{"id":"NPM-test","affected":[{"package":{"ecosystem":"npm","name":"example-lib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.2.0"},{"last_affected":"1.1.0"}]}]}]}`),
		report.EcosystemPyPI: snapshotZIP(t, "PYSEC-test", `{"id":"PYSEC-test","affected":[{"package":{"ecosystem":"PyPI","name":"Sample_pkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1!2.0rc1"},{"fixed":"1!2.0"}]}]}]}`),
	}
	o := osv.DefaultOptions()
	o.Enabled = true
	var err error
	o.Snapshot, err = osv.LoadSnapshot(t.Context(), archives)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	dependencies := report.DependencyReport{Declarations: []report.Dependency{
		snapshotDependency("go-vulnerable", report.EcosystemGo, "example.org/lib", "v1.1.0"),
		snapshotDependency("go-fixed", report.EcosystemGo, "example.org/lib", "v1.2.0"),
		snapshotDependency("python", report.EcosystemPyPI, "sample-pkg", "1!2.0rc2"),
		snapshotDependency("npm-last", report.EcosystemNPM, "example-lib", "1.1.0"),
		snapshotDependency("npm-limit", report.EcosystemNPM, "example-lib", "1.2.0"),
	}}
	result, err := osv.Check(t.Context(), dependencies, o, now)
	if err != nil || result.Completeness != report.Complete || len(result.Matches) != 3 || len(result.Snapshots) != 3 {
		t.Fatalf("unexpected snapshot results: %+v, %v", result, err)
	}
	match := result.Matches[0]
	if match.ID != "GO-test" || match.Severity != report.Medium || match.Summary != "Go advisory" || len(match.Aliases) != 1 {
		t.Fatalf("lost advisory details: %+v", match)
	}
	for _, m := range result.Matches {
		if len(m.DependencyIDs) != 1 || m.DependencyIDs[0] == "go-fixed" || m.DependencyIDs[0] == "npm-limit" {
			t.Fatalf("matched an unaffected version: %+v", m)
		}
	}
	exported, err := osv.Export(result)
	if err != nil || len(exported.Records) != 0 {
		t.Fatalf("snapshot results became timestamped exact cache records: %+v, %v", exported, err)
	}

	o.AllowNetwork = true
	if _, err := osv.Check(t.Context(), dependencies, o, now); err == nil {
		t.Fatal("snapshot unexpectedly allowed network")
	}
}

func TestInvalidSnapshotCoordinatesRemainIncomplete(t *testing.T) {
	db, err := osv.LoadSnapshot(t.Context(), map[string]osv.SnapshotArchive{
		report.EcosystemNPM: snapshotZIP(t, "NPM-test", `{"id":"NPM-test","affected":[{"package":{"ecosystem":"npm","name":"some-lib"},"ranges":[{"type":"GIT","events":[{"introduced":"0"}]},{"type":"GIT","events":[{"introduced":"0"}]}]}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	o := osv.DefaultOptions()
	o.Enabled, o.Snapshot = true, db
	result, err := osv.Check(t.Context(), report.DependencyReport{Declarations: []report.Dependency{
		snapshotDependency("unknown", report.EcosystemNPM, "some-lib", "1.0.0"),
		snapshotDependency("bundled", report.EcosystemPyPI, "requests", "2.31.0"),
	}}, o, time.Now())
	if err != nil || result.Completeness != report.Partial || len(result.Matches) != 1 ||
		result.Queries[0].Status != "snapshot_incomplete" || result.Queries[1].Status != report.OutcomeBundledMatch {
		t.Fatalf("unsupported data became clean coverage: %+v, %v", result, err)
	}
}

func TestSnapshotChoosesHighestSeverityAmongMatchingEntries(t *testing.T) {
	data := `{"id":"NPM-test","affected":[
		{"package":{"ecosystem":"npm","name":"example-lib"},"versions":["1.0.0+first"],"database_specific":{"severity":"LOW"}},
		{"package":{"ecosystem":"npm","name":"example-lib"},"versions":["1.0.0+first","1.1.0"],"database_specific":{"severity":"HIGH"}},
		{"package":{"ecosystem":"npm","name":"example-lib"},"versions":["1.1.0"],"database_specific":{"severity":"CRITICAL"}}
	]}`
	db, err := osv.LoadSnapshot(t.Context(), map[string]osv.SnapshotArchive{
		report.EcosystemNPM: snapshotZIP(t, "NPM-test", data),
	})
	if err != nil {
		t.Fatal(err)
	}
	o := osv.DefaultOptions()
	o.Enabled, o.Snapshot = true, db
	deps := report.DependencyReport{Declarations: []report.Dependency{
		snapshotDependency("first", report.EcosystemNPM, "example-lib", "1.0.0+first"),
		snapshotDependency("different-build", report.EcosystemNPM, "example-lib", "1.0.0+second"),
		snapshotDependency("newer", report.EcosystemNPM, "example-lib", "1.1.0"),
	}}
	got, err := osv.Check(t.Context(), deps, o, time.Now())
	if err != nil || got.Completeness != report.Complete || len(got.Matches) != 2 ||
		got.Matches[0].DependencyIDs[0] != "first" || got.Matches[0].Severity != report.High ||
		got.Matches[1].DependencyIDs[0] != "newer" || got.Matches[1].Severity != report.Critical {
		t.Fatalf("unexpected snapshot results: %+v, %v", got, err)
	}
}

func TestOnlineDetailsShareBudgetAndRetainPositiveMatches(t *testing.T) {
	for _, maxRequests := range []int{1, 2, 3} {
		t.Run(string(rune('0'+maxRequests)), func(t *testing.T) {
			calls := make(chan string, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- r.Method + " " + r.URL.Path
				switch r.URL.Path {
				case "/v1/querybatch":
					_, _ = io.WriteString(w, `{"results":[{"vulns":[{"id":"OSV-demo"}]},{"vulns":[{"id":"OSV-demo"}]}]}`)
				case "/v1/vulns/OSV-demo":
					if maxRequests == 2 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_, _ = io.WriteString(w, `{"id":"OSV-demo","summary":"Advisory details","aliases":["CVE-fixture","CVE-fixture"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			o := osv.DefaultOptions()
			o.Enabled, o.AllowNetwork, o.AllowLoopback = true, true, true
			o.Endpoint, o.MaxRequests = server.URL+"/v1/querybatch", maxRequests
			got, err := osv.Check(t.Context(), report.DependencyReport{Declarations: []report.Dependency{
				snapshotDependency("first", report.EcosystemNPM, "first", "1.0.0"),
				snapshotDependency("second", report.EcosystemNPM, "second", "1.0.0"),
			}}, o, time.Now())
			if err != nil || len(got.Matches) != 2 || got.Completeness != report.Complete {
				t.Fatalf("lost exact lookup coverage: %+v, %v", got, err)
			}
			if callsCount := len(calls); callsCount != min(maxRequests, 2) {
				t.Fatalf("%d requests with budget %d", callsCount, maxRequests)
			}
			for _, match := range got.Matches {
				if maxRequests < 3 && match.Severity != "" || maxRequests == 3 && (match.Severity != report.Critical || !strings.Contains(match.Summary, "details") || len(match.Aliases) != 1) {
					t.Fatalf("unexpected detail: %+v", match)
				}
			}
		})
	}
}

func TestOnlineDetailsFollowVersionAndSurviveCacheExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = io.WriteString(w, `{"results":[{"vulns":[{"id":"OSV-demo"}]},{"vulns":[{"id":"OSV-demo"}]}]}`)
		case "/v1/vulns/OSV-demo":
			_, _ = io.WriteString(w, `{"id":"OSV-demo","summary":"Advisory details","aliases":["CVE-fixture"],"affected":[
				{"package":{"ecosystem":"npm","name":"example"},"versions":["1.0.0"],"database_specific":{"severity":"LOW"}},
				{"package":{"ecosystem":"npm","name":"example"},"versions":["2.0.0"],"database_specific":{"severity":"CRITICAL"}}
			]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	o := osv.DefaultOptions()
	o.Enabled, o.AllowNetwork, o.AllowLoopback = true, true, true
	o.Endpoint = server.URL + "/v1/querybatch"
	deps := report.DependencyReport{Declarations: []report.Dependency{
		snapshotDependency("first", report.EcosystemNPM, "example", "1.0.0"),
		snapshotDependency("second", report.EcosystemNPM, "example", "2.0.0"),
	}}
	now := time.Now()
	online, err := osv.Check(t.Context(), deps, o, now)
	if err != nil || len(online.Matches) != 2 || online.Matches[0].Severity != report.Low || online.Matches[1].Severity != report.Critical {
		t.Fatalf("unexpected online version severity: %+v, %v", online, err)
	}
	cache, err := osv.Export(online)
	if err != nil {
		t.Fatal(err)
	}
	o.Offline, err = json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	o.AllowNetwork = false
	offline, err := osv.Check(t.Context(), deps, o, now)
	if err != nil || offline.Completeness != report.Complete || len(offline.Matches) != 2 {
		t.Fatalf("unexpected cached results: %+v, %v", offline, err)
	}
	for i, match := range offline.Matches {
		if match.Severity != online.Matches[i].Severity || match.Summary != "Advisory details" || len(match.Aliases) != 1 || match.Aliases[0] != "CVE-fixture" {
			t.Fatalf("detail changed in cache: %+v", match)
		}
	}
}

func snapshotZIP(t *testing.T, id, record string) osv.SnapshotArchive {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	member, err := writer.Create(id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(member, record); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return osv.SnapshotArchive{Reader: bytes.NewReader(data.Bytes()), Size: int64(data.Len())}
}

func snapshotDependency(id, ecosystem, name, version string) report.Dependency {
	return report.Dependency{
		ID: id, Ecosystem: ecosystem, Module: name, DeclaredVersion: version,
		VersionSemantics: report.VersionExactLockfile,
	}
}
