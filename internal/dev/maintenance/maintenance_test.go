package maintenance_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		"internal/dev/maintenance/maintenance.go":      "package maintenance\n",
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

func TestSourceVerificationRejectsMutableReferences(t *testing.T) {
	root := t.TempDir()
	write(t, root, "knowledge/data/review_sources.json", []byte(`[{"id":"x","repository":"https://github.com/example/repo","revision":"main","artifacts":[]}]`))
	var out bytes.Buffer
	if err := maintenance.Run(t.Context(), []string{"verify-knowledge-sources", "--root", root, "--cache", t.TempDir()}, &out, &out); err == nil {
		t.Fatal("mutable source revision accepted")
	}
}

func TestMaintenanceRejectsRemovedExternalCommands(t *testing.T) {
	for _, command := range []string{
		"compare-upstream", "run-upstream-suite", "compare-upstream-suite",
		"adjudicate-upstream-suite", "network-denial-probe",
	} {
		var out bytes.Buffer
		err := maintenance.Run(t.Context(), []string{command}, &out, &out)
		if err == nil || !strings.Contains(err.Error(), "unknown maintenance command") {
			t.Fatalf("removed command %s was accepted: %v", command, err)
		}
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
