package maintenance_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/dev/maintenance"
)

func TestRuntimeInventoryIncludesInactiveSourcesAndNewEmbeddedAssets(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod": "module example.invalid/scout\n\ngo 1.26.0\n", "go.sum": "",
		"scan.go":                                      "package scout\nimport _ \"example.invalid/scout/internal/analysis/engine\"\n",
		"internal/analysis/engine/engine.go":           "package engine\n",
		"internal/analysis/engine/core.go":             "//go:build coreonly\n\npackage engine\n",
		"internal/analysis/engine/native.go":           "//go:build !coreonly\n\npackage engine\nimport _ \"example.invalid/scout/internal/extra\"\n",
		"internal/analysis/engine/platform_windows.go": "package engine\n",
		"internal/extra/embed.go":                      "package extra\nimport _ \"embed\"\n//go:embed data/*.txt\nvar data string\n",
		"internal/extra/data/instructions.txt":         "trusted embedded instructions\n",
		"internal/extra/extra_test.go":                 "package extra\n",
		"internal/dev/maintenance/adjudication.go":     "package maintenance\n",
		"cmd/scout/main.go":                            "package main\nimport _ \"example.invalid/scout\"\nfunc main(){}\n",
		"cmd/scout-dev/main.go":                        "package main\nimport _ \"example.invalid/scout/internal/devonly\"\nfunc main(){}\n",
		"internal/devonly/dev.go":                      "package devonly\n",
	}
	expected := make([]string, 0)
	for name, content := range files {
		write(t, root, name, []byte(content))
		if !strings.HasSuffix(name, "_test.go") && !strings.HasPrefix(name, "internal/dev/maintenance/") && !strings.HasPrefix(name, "cmd/scout-dev/") && !strings.HasPrefix(name, "internal/devonly/") {
			expected = append(expected, filepath.Join(root, name))
		}
	}
	slices.Sort(expected)
	actual, err := maintenance.ScannerRuntimeFiles(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actual, expected) {
		t.Fatalf("inventory lost build inputs:\ngot %v\nwant %v", actual, expected)
	}
	developer, err := maintenance.DeveloperRuntimeFiles(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	wantDeveloper := []string{filepath.Join(root, "cmd/scout-dev/main.go"), filepath.Join(root, "internal/devonly/dev.go")}
	if !slices.Equal(developer, wantDeveloper) {
		t.Fatalf("developer closure=%v want %v", developer, wantDeveloper)
	}
	write(t, root, "internal/devonly/dev.go", []byte("package devonly\nfunc Changed() {}\n"))
	afterDeveloperChange, err := maintenance.ScannerRuntimeFiles(t.Context(), root)
	if err != nil || !slices.Equal(afterDeveloperChange, actual) {
		t.Fatal("developer change altered product closure", err)
	}
	added := "internal/extra/data/added.txt"
	write(t, root, added, []byte("new asset"))
	expected = append(expected, filepath.Join(root, added))
	slices.Sort(expected)
	actual, err = maintenance.ScannerRuntimeFiles(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actual, expected) {
		t.Fatal("new embedded asset was not inventoried")
	}
	write(t, root, "scan.go", []byte("package scout\n"))
	if _, err = maintenance.ScannerRuntimeFiles(t.Context(), root); err == nil {
		t.Fatal("incomplete graph was accepted")
	}
}

func TestSavedCapturePreparationAndComparison(t *testing.T) {
	for _, tc := range []struct {
		name, file, canonicalFile string
		content                   []byte
	}{
		{name: "empty", file: "empty.txt", canonicalFile: `"empty.txt"`, content: []byte{}},
		{
			name:          "ascii-id-contract",
			file:          "é\x7f😀.txt",
			canonicalFile: `"\u00e9\u007f\ud83d\ude00.txt"`,
			content:       []byte("saved input"),
		},
		{
			name:          "unicode-byte-budget",
			file:          "unicode.txt",
			canonicalFile: `"unicode.txt"`,
			content:       []byte(strings.Repeat("界", 400000)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testSavedCapture(t, tc.file, tc.canonicalFile, tc.content)
		})
	}
}

func TestSourceVerificationRejectsMutableReferences(t *testing.T) {
	root := t.TempDir()
	write(t, root, "knowledge/data/review_sources.json", []byte(`[{"id":"x","repository":"https://github.com/example/repo","revision":"main","artifacts":[]}]`))
	var out bytes.Buffer
	if err := maintenance.Run(t.Context(), []string{"verify-knowledge-sources", "--root", root, "--cache", t.TempDir()}, &out, &out); err == nil {
		t.Fatal("mutable source revision accepted")
	}
}

func TestSuiteRunnerRefusesRemovedMonitoringFlag(t *testing.T) {
	var out bytes.Buffer
	if err := maintenance.Run(t.Context(), []string{"run-upstream-suite", "--capture"}, &out, &out); err == nil {
		t.Fatal("removed runtime monitoring flag silently accepted")
	}
}

func write(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func testSavedCapture(t *testing.T, file, canonicalFile string, content []byte) {
	t.Helper()
	root := t.TempDir()
	capture, replay := filepath.Join(root, "capture"), filepath.Join(root, "replay")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	descriptor := map[string]any{"sha256": hash, "bytes": len(content), "representation": "utf8"}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	write(t, capture, "blobs/"+hash+".gz", compressed.Bytes())
	write(t, capture, "capture-summary.json", []byte(`{"exit_status":0,"capture_errors":[]}`))
	observation := map[string]any{
		"id":                "observation",
		"test":              "tests/test_sample.py::test_empty",
		"module":            "sample",
		"function":          "analyze",
		"files":             map[string]any{file: descriptor},
		"families":          []string{"P1"},
		"context_flags":     []string{},
		"upstream_findings": []any{map[string]any{"rule": "P1"}},
	}
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	write(t, capture, "observations.jsonl", append(data, '\n'))
	write(t, capture, "collection.json", []byte(`{"tests":[{"test":"tests/test_sample.py::test_empty"}]}`))
	write(t, capture, "test-status.jsonl", []byte("{\"test\":\"tests/test_sample.py::test_empty\",\"phase\":\"call\",\"outcome\":\"passed\"}\n"))
	var out, errout bytes.Buffer
	args := []string{"compare-upstream-suite", "prepare", "--root", root, "--capture", capture, "--replay", replay}
	if err = maintenance.Run(t.Context(), args, &out, &errout); err != nil {
		t.Fatal(err)
	}
	var index struct{ Groups []struct{ ID string } }
	read(t, filepath.Join(replay, "index.json"), &index)
	// This exact sorted ASCII JSON format is the existing capture ID contract.
	canonical := `{` + canonicalFile + `: {"bytes": ` + strconv.Itoa(len(content)) + `, "representation": "utf8", "sha256": "` + hash + `"}}`
	expected := sha256.Sum256([]byte(canonical))
	if len(index.Groups) != 1 || index.Groups[0].ID != hex.EncodeToString(expected[:]) {
		t.Fatal("saved capture IDs changed", index)
	}
	var input struct {
		Files []struct {
			Name string
			Data []byte
		}
	}
	inputBytes, err := os.ReadFile(filepath.Join(replay, "input.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Files) != 1 || input.Files[0].Name != file || !bytes.Equal(input.Files[0].Data, content) {
		t.Fatal("saved input bytes changed")
	}
	result := `{"id":"` + index.Groups[0].ID + `","version":"0.22.0-preview","findings":[],"coverage":"partial","decision":"review","diagnostics":[]}`
	results, comparison := filepath.Join(root, "results.jsonl"), filepath.Join(root, "differences.json")
	write(t, root, "results.jsonl", []byte(result+"\n"))
	args = []string{"compare-upstream-suite", "compare", "--root", root, "--capture", capture, "--replay", replay, "--results", results, "--output", comparison}
	if err = maintenance.Run(t.Context(), args, &out, &errout); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Scanned     int `json:"scanned_inputs"`
		Differences []struct {
			Missing  []string
			Boundary string `json:"boundary_kind"`
		}
	}
	read(t, comparison, &report)
	if report.Scanned != 1 || len(report.Differences) != 1 || !slices.Equal(report.Differences[0].Missing, []string{"P1"}) || report.Differences[0].Boundary != "public_or_direct_analyzer" {
		t.Fatal("comparison dropped a missing observation", report)
	}
	write(t, root, "results.jsonl", []byte(result+"\n"+result+"\n"))
	if err = maintenance.Run(t.Context(), args, &out, &errout); err == nil {
		t.Fatal("duplicate replay results accepted")
	}
	broken := `{"id":"` + index.Groups[0].ID + `","version":"` + scout.Version() + `","state":"failed","findings":[],"coverage":"complete","decision":"allow","diagnostics":[]}`
	write(t, root, "results.jsonl", []byte(broken+"\n"))
	if err = maintenance.Run(t.Context(), args, &out, &errout); err == nil {
		t.Fatal("comparison accepted a failed current replay without budget or run binding")
	}
}
