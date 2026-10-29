package scout_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

// A newer upstream snapshot must not silently reuse an older suite coverage claim.
func TestUpstreamSuiteInventoryMatchesPinnedSource(t *testing.T) {
	var inventory struct {
		Commit string
		Files  []struct{ Path, SHA256 string }
	}
	var report struct {
		Commit    string `json:"upstream_commit"`
		Collected int    `json:"collected_cases"`
		Files     []struct {
			Path, SHA256 string
			Cases        int `json:"collected_cases"`
		} `json:"test_files"`
	}
	load := func(name string, out any) {
		t.Helper()
		data, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(data, out); e != nil {
			t.Fatal(e)
		}
	}
	load("../../testdata/provenance/upstream-inventory.json", &inventory)
	load("../../testdata/provenance/upstream-suite-0.20.json", &report)
	if report.Commit == "" || report.Commit != inventory.Commit {
		t.Fatal("suite source revision drift")
	}
	expected := map[string]string{}
	for _, f := range inventory.Files {
		if strings.HasPrefix(f.Path, "tests/") && strings.HasPrefix(path.Base(f.Path), "test_") && strings.HasSuffix(f.Path, ".py") {
			expected[f.Path] = f.SHA256
		}
	}
	seen := map[string]bool{}
	cases := 0
	for _, f := range report.Files {
		if seen[f.Path] || expected[f.Path] == "" || expected[f.Path] != f.SHA256 || f.Cases < 1 {
			t.Fatal("missing/changed/duplicate test module", f.Path)
		}
		seen[f.Path] = true
		cases += f.Cases
	}
	if len(seen) != len(expected) || cases != report.Collected || cases == 0 {
		t.Fatal("incomplete suite module/case accounting")
	}
}

// Compatibility decisions must not outlive their source revision, input set or
// scanner implementation silently. This is evidence accounting, not an oracle
// that blesses every finding or equates incomplete scans with clean results.
func TestUpstreamAdjudicationAccountsForPreviousDeltas(t *testing.T) {
	var ledger struct {
		Commit       string `json:"upstream_commit"`
		Version      string `json:"scout_version"`
		Before       int    `json:"before_observations"`
		After        int    `json:"after_observations"`
		Union        int    `json:"union_observations"`
		Inputs       int    `json:"scanned_inputs"`
		Unclassified int    `json:"unclassified_deltas"`
		BeforeSHA    string `json:"before_sha256"`
		BeforeIDsSHA string `json:"before_ids_sha256"`
		Reasons      map[string]struct {
			Disposition, Meaning string
			Code                 string `json:"scout_code"`
		} `json:"reasons"`
		Counts map[string]int `json:"reason_counts"`
		Sites  []struct {
			File, SHA256 string
			Line         int
		} `json:"test_sites"`
		Runtime  []struct{ Path, SHA256 string } `json:"runtime_files"`
		InputIDs []string                        `json:"inputs"`
		Rows     [][]json.RawMessage             `json:"rows"`
	}
	var previous struct {
		Commit string `json:"upstream_commit"`
		Replay struct {
			Summary struct {
				Differing int `json:"differing_observations"`
			} `json:"summary"`
		} `json:"replay"`
		Artifacts map[string]struct {
			SHA string `json:"uncompressed_sha256"`
		} `json:"artifacts"`
	}
	var inventory struct {
		Commit string
		Files  []struct{ Path, SHA256 string }
	}
	load := func(path string, out any) {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, out); e != nil {
			t.Fatal(e)
		}
	}
	load("../../testdata/provenance/upstream-adjudication-0.22.json", &ledger)
	load("../../testdata/provenance/upstream-suite-0.21.json", &previous)
	load("../../testdata/provenance/upstream-inventory.json", &inventory)
	if ledger.Version != "0.22.0-preview" || ledger.Commit != inventory.Commit || ledger.Commit != previous.Commit || ledger.Unclassified != 0 || ledger.Inputs != 14930 || ledger.Before != previous.Replay.Summary.Differing || ledger.Union != len(ledger.Rows) || ledger.After < 1 || ledger.BeforeSHA != previous.Artifacts["differences"].SHA {
		t.Fatal("adjudication provenance/coverage drift")
	}
	sources := map[string]string{}
	for _, f := range inventory.Files {
		sources[f.Path] = f.SHA256
	}
	for _, s := range ledger.Sites {
		if s.Line < 1 || sources[s.File] == "" || sources[s.File] != s.SHA256 {
			t.Fatal("unverified upstream test site", s.File)
		}
	}
	// This is historical evidence: compare the ledger with its archived source
	// bytes, never substitute hashes from the new implementation into old claims.
	historical := historicalRuntime(t)
	if len(historical) != len(ledger.Runtime) {
		t.Fatal("historical runtime inventory drift")
	}
	for _, f := range ledger.Runtime {
		b, ok := historical[f.Path]
		if !ok {
			t.Fatal("historical source missing", f.Path)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Fatal("historical source checksum drift", f.Path)
		}
	}

	seen, before, counts := map[string]bool{}, make([]string, 0), map[string]int{}
	for _, row := range ledger.Rows {
		if len(row) != 15 {
			t.Fatal("invalid ledger row")
		}
		var id string
		var site, input int
		var bm, be, am, ae []string
		var decisions [][]string
		var inBefore bool
		for _, pair := range []struct {
			at int
			to any
		}{{at: 0, to: &id}, {at: 1, to: &site}, {at: 2, to: &input}, {at: 5, to: &bm}, {at: 6, to: &be}, {
			at: 7,
			to: &am,
		}, {
			at: 8,
			to: &ae,
		}, {
			at: 12,
			to: &decisions,
		}, {
			at: 13,
			to: &inBefore,
		}} {
			if e := json.Unmarshal(row[pair.at], pair.to); e != nil {
				t.Fatal(e)
			}
		}
		if seen[id] || len(id) != 64 || site < 0 || site >= len(ledger.Sites) || input < 0 || input >= len(ledger.InputIDs) {
			t.Fatal("duplicate/unlinked observation", id)
		}
		seen[id] = true
		if inBefore {
			before = append(before, id)
		}
		expected := map[string]bool{}
		for _, r := range append(bm, am...) {
			expected["missing:"+r] = true
		}
		for _, r := range append(be, ae...) {
			expected["extra:"+r] = true
		}
		if len(expected) == 0 {
			expected["input:replay"] = true
		}
		for _, d := range decisions {
			if len(d) != 3 || !expected[d[0]+":"+d[1]] || ledger.Reasons[d[2]].Disposition == "" || ledger.Reasons[d[2]].Meaning == "" {
				t.Fatal("unreviewed/duplicate delta", id)
			}
			delete(expected, d[0]+":"+d[1])
			counts[d[2]]++
		}
		if len(expected) > 0 {
			t.Fatal("unaccounted delta", id)
		}
	}
	sort.Strings(before)
	sum := sha256.Sum256([]byte(strings.Join(before, "\n") + "\n"))
	if len(before) != ledger.Before || hex.EncodeToString(sum[:]) != ledger.BeforeIDsSHA {
		t.Fatal("previous observation lost")
	}
	for key, n := range ledger.Counts {
		if counts[key] != n {
			t.Fatal("decision count drift", key)
		}
		delete(counts, key)
	}
	if len(counts) > 0 {
		t.Fatal("unreported decisions")
	}
}

func historicalRuntime(t *testing.T) map[string][]byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/provenance/scout-0.22-runtime.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != "fbc9ae1a97de73eeb10fa6d6c97dfdb141ece23bb7a25d440be6f9e3dd1b2d78" {
		t.Fatal("historical source archive checksum drift")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := gz.Close(); err != nil {
			t.Error(err)
		}
	}()
	archive := tar.NewReader(io.LimitReader(gz, 8<<20))
	out := map[string][]byte{}
	for {
		h, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || h.Size > 1<<20 || out[h.Name] != nil {
			t.Fatal("invalid historical archive member")
		}
		b, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = b
	}
	return out
}
