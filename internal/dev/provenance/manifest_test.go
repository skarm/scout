//nolint:testpackage // Exercises private implementation details and package fixtures.
package provenance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

// Exercise the acceptance contract through generation and both verification
// modes. A private miniature module keeps this independent of the worktree.
func TestGenerateVerifyAndSourceMutation(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"go.mod": "module example.invalid/receipt\n\ngo 1.26.0\n", "go.sum": "",
		"scan.go":                            "package receipt\nimport _ \"example.invalid/receipt/internal/analysis/engine\"\n",
		"internal/analysis/engine/engine.go": "package engine\n",
		"internal/analysis/engine/native.go": "//go:build !coreonly && cgo\n\npackage engine\nimport \"C\"\n",
		"internal/analysis/engine/native.c":  "//go:build !coreonly && cgo\n\nint scout_fixture(void) { return 1; }\n",
		"internal/analysis/engine/native.h":  "int scout_fixture(void);\n",
		"cmd/scout/main.go":                  "package main\nimport _ \"example.invalid/receipt\"\nfunc main(){}\n",
		"cmd/scout-dev/main.go":              "package main\nfunc main(){}\n",
	}
	for path, source := range files {
		write(path, []byte(source))
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "."},
		{"-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "source fixture"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v: %s", err, output)
		}
	}
	id := strings.Repeat("a", 64)
	row := replayRow{
		ID:            id,
		Version:       "fixture",
		BudgetSeconds: 5,
		State:         report.RunComplete,
		Coverage:      report.Complete,
		Decision:      report.Allow,
		RunDigest:     "sha256:" + strings.Repeat("0", 64),
		Findings:      []report.Finding{},
		Diagnostics:   []string{},
	}
	encode := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		write(path, append(data, '\n'))
	}
	encode("input.jsonl", struct {
		ID    string `json:"id"`
		Files []any  `json:"files"`
	}{ID: id, Files: []any{}})
	encode("before.jsonl", row)
	encode("after.jsonl", row)
	comparison, err := Compare(t.Context(), root, "before.jsonl", "after.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	encode("comparison.json", comparison)
	encode("summary.json", summary{Inputs: 1, Complete: 1})
	encode("release.json", map[string]any{
		"passed": true,
		"selftest": map[string]any{
			"passed":  true,
			"version": "fixture",
		},
	})
	opts := Options{
		Root:         root,
		Version:      "fixture",
		Input:        "input.jsonl",
		Replay:       "after.jsonl",
		Summary:      "summary.json",
		Releasecheck: "release.json",
		Comparison:   "comparison.json",
	}
	m, err := Generate(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Summary.Inputs != 1 || m.Summary.Complete != 1 || !m.SourceDirty || len(m.ProductSources) != 8 || len(m.DeveloperSources) != 1 {
		t.Fatalf("incorrect source-bound receipt: %+v", m)
	}
	encode("manifest.json", m)
	loaded, err := Read(root, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []Verification{
		{Version: "fixture", InputMode: InputFile},
		{Version: "fixture", InputMode: InputFile, CurrentSources: true},
		{
			Version:   "fixture",
			InputMode: inputPinned,
			InputPin:  file{Path: m.Input.Path, SHA256: m.Input.SHA256},
			IDsSHA256: m.InputIDsSHA256,
		},
	} {
		if err := Verify(t.Context(), root, loaded, expected); err != nil {
			t.Fatal(err)
		}
	}
	invalid := []func(*Manifest){
		func(m *Manifest) { m.Schema = "other" }, func(m *Manifest) { m.Version = "other" },
		func(m *Manifest) { m.SourceCommit = "bad" }, func(m *Manifest) { m.Summary.Inputs = 0 },
		func(m *Manifest) { m.InputIDsSHA256 = "bad" }, func(m *Manifest) { m.Replay.UncompressedSHA256 = "bad" },
		func(m *Manifest) { m.ProductSources = nil }, func(m *Manifest) { m.DeveloperSources = nil },
		func(m *Manifest) { m.ProductSources = []file{{Path: "../outside.go", SHA256: strings.Repeat("a", 64)}} },
		func(m *Manifest) { m.ProductSources = []file{{Path: "scan.go", SHA256: "invalid"}} },
		func(m *Manifest) { m.DeveloperSources = m.ProductSources },
		func(m *Manifest) { m.Summary.Findings++ },
	}
	for i, change := range invalid {
		bad := m
		change(&bad)
		if Verify(t.Context(), root, bad, Verification{Version: "fixture", InputMode: InputFile}) == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	write("internal/analysis/engine/engine.go", []byte("package engine\nfunc Changed(){}\n"))
	if err := Verify(t.Context(), root, m, Verification{Version: "fixture", InputMode: InputFile}); err != nil {
		t.Fatalf("editing current source invalidated recorded evidence: %v", err)
	}
	if Verify(t.Context(), root, m, Verification{Version: "fixture", InputMode: InputFile, CurrentSources: true}) == nil {
		t.Fatal("source replacement accepted")
	}
	write("internal/analysis/engine/engine.go", []byte(files["internal/analysis/engine/engine.go"]))
	for _, path := range []string{"internal/analysis/engine/native.c", "internal/analysis/engine/native.h"} {
		write(path, []byte(files[path]+"\n// changed native source\n"))
		if Verify(t.Context(), root, m, Verification{Version: "fixture", InputMode: InputFile, CurrentSources: true}) == nil {
			t.Fatalf("native source replacement accepted: %s", path)
		}
		write(path, []byte(files[path]))
	}
	if _, err := Generate(nil, opts); err == nil {
		t.Fatal("nil generation context accepted")
	}
	if err := Verify(context.Background(), root, m, Verification{Version: "other", InputMode: InputFile}); err == nil {
		t.Fatal("foreign receipt accepted")
	}
}

func TestRecordedVerificationNeedsEvidenceButNoSourceCheckout(t *testing.T) {
	fixture := verificationArtifactFixture(t)
	m := fixture.manifest
	m.Schema = schema
	m.SourceCommit = strings.Repeat("c", 40)
	m.ProductSources = []file{{Path: "recorded.go", SHA256: strings.Repeat("d", 64)}}
	m.DeveloperSources = []file{{Path: "tools/recorded.go", SHA256: strings.Repeat("e", 64)}}
	m.Input = fixture.write(t, "input.jsonl", map[string]any{
		"id": strings.Repeat("a", 64), "files": []any{},
	})
	m.InputIDsSHA256 = idsDigest(fixture.observed.ids)
	expected := Verification{Version: m.Version, InputMode: InputFile}
	if err := Verify(t.Context(), fixture.root, m, expected); err != nil {
		t.Fatal("recorded evidence required a source checkout", err)
	}

	expected.CurrentSources = true
	if err := Verify(t.Context(), fixture.root, m, expected); err == nil {
		t.Fatal("explicit checkout audit accepted missing sources")
	}

	expected.CurrentSources = false
	fixture.writeBytes(t, "after.jsonl", []byte("corrupted evidence\n"))
	if err := Verify(t.Context(), fixture.root, m, expected); err == nil {
		t.Fatal("recorded verification accepted corrupted replay bytes")
	}
}

func TestVerificationBindsAccountingAndArtifactBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *verificationArtifacts)
	}{
		{
			name:   "provenance-accounting",
			change: func(t *testing.T, f *verificationArtifacts) { f.manifest.Summary.Findings++ },
		},
		{name: "provenance-error-counts", change: func(t *testing.T, f *verificationArtifacts) {
			f.manifest.ErrorCounts = map[string]int{"replay_runtime_error": 1}
		}},
		{name: "summary-bytes-changed", change: func(t *testing.T, f *verificationArtifacts) {
			f.write(t, "summary.json", summary{Inputs: 7, Failed: 7})
		}},
		{name: "summary-shape", change: func(t *testing.T, f *verificationArtifacts) {
			f.manifest.SummaryArtifact = f.write(t, "summary.json", map[string]any{
				"inputs":     1,
				"unexpected": "unaccepted",
			})
		}},
		{name: "summary-accounting", change: func(t *testing.T, f *verificationArtifacts) {
			f.manifest.SummaryArtifact = f.write(t, "summary.json", summary{Inputs: 1, Failed: 1, RuntimeErrors: 1})
		}},
		{name: "release-bytes-changed", change: func(t *testing.T, f *verificationArtifacts) {
			f.write(t, "release.json", map[string]bool{"passed": true})
		}},
		{name: "release-invalid-json", change: func(t *testing.T, f *verificationArtifacts) {
			f.manifest.Releasecheck = f.writeBytes(t, "release.json", []byte(`{"passed":true`))
		}},
		{name: "comparison-unavailable", change: func(t *testing.T, f *verificationArtifacts) {
			if err := os.Remove(filepath.Join(f.root, "comparison.json")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := verificationArtifactFixture(t)
			tc.change(t, fixture)
			if err := verifyArtifacts(t.Context(), fixture.root, fixture.manifest, fixture.observed, false); err == nil {
				t.Fatal("receipt accepted altered accounting or artifact")
			}
		})
	}
}

func TestVerificationRequiresBothAcceptanceResultsForTheBoundVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		release any
	}{
		{
			name: "release-failed",
			release: map[string]any{
				"passed": false,
				"selftest": map[string]any{
					"passed":  true,
					"version": "acceptance-fixture",
				},
			},
		},
		{
			name: "selftest-failed",
			release: map[string]any{
				"passed": true,
				"selftest": map[string]any{
					"passed":  false,
					"version": "acceptance-fixture",
				},
			},
		},
		{name: "selftest-missing", release: map[string]any{"passed": true}},
		{
			name: "selftest-version",
			release: map[string]any{
				"passed": true,
				"selftest": map[string]any{
					"passed":  true,
					"version": "another-version",
				},
			},
		},
		{
			name:    "prose-only",
			release: map[string]string{"description": "release and selftest passed for acceptance-fixture"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := verificationArtifactFixture(t)
			fixture.manifest.Releasecheck = fixture.write(t, "release.json", tc.release)
			if err := verifyArtifacts(t.Context(), fixture.root, fixture.manifest, fixture.observed, false); err == nil {
				t.Fatal("unsupported acceptance admitted")
			}
		})
	}
}

type verificationArtifacts struct {
	root     string
	manifest Manifest
	observed replayEvidence
}

func (f *verificationArtifacts) write(t *testing.T, path string, value any) artifact {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return f.writeBytes(t, path, append(data, '\n'))
}

func (f *verificationArtifacts) writeBytes(t *testing.T, path string, data []byte) artifact {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, path), data, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := artifactIdentity(t.Context(), f.root, path)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func verificationArtifactFixture(t *testing.T) *verificationArtifacts {
	t.Helper()
	f := &verificationArtifacts{root: t.TempDir()}
	row := replayRow{
		ID:            strings.Repeat("a", 64),
		Version:       "acceptance-fixture",
		BudgetSeconds: 5,
		State:         report.RunComplete,
		Coverage:      report.Complete,
		Decision:      report.Allow,
		RunDigest:     "sha256:" + strings.Repeat("b", 64),
		Findings:      []report.Finding{},
		Diagnostics:   []string{},
	}
	f.write(t, "before.jsonl", row)
	replay := f.write(t, "after.jsonl", row)
	observed, err := readReplay(t.Context(), f.root, replay, row.Version)
	if err != nil {
		t.Fatal(err)
	}
	replay.UncompressedSHA256 = observed.contentSHA256
	comparison, err := Compare(t.Context(), f.root, "before.jsonl", "after.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	f.observed = observed
	f.manifest = Manifest{
		Version: row.Version, Replay: replay, Summary: observed.summary, ErrorCounts: observed.errors,
		SummaryArtifact: f.write(t, "summary.json", observed.summary),
		Releasecheck: f.write(t, "release.json", map[string]any{
			"passed": true,
			"selftest": map[string]any{
				"passed":  true,
				"version": row.Version,
			},
			"linkage": map[string]any{"measured": "additional receipt fields remain supported"},
		}),
		Comparison: f.write(t, "comparison.json", comparison),
	}
	if err := verifyArtifacts(t.Context(), f.root, f.manifest, f.observed, false); err != nil {
		t.Fatal("valid receipt fixture rejected", err)
	}
	return f
}
