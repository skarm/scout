package architecture_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Source pointers in live embedded metadata refer to this repository. Upstream
// source names and historical receipts retain their separate identities.
func TestEmbeddedScoutSourcePointersResolve(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string, destination any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, destination); err != nil {
			t.Fatal(err)
		}
	}
	check := func(label, value string) {
		t.Helper()
		for part := range strings.SplitSeq(value, ";") {
			path, _, _ := strings.Cut(strings.TrimSpace(part), "#")
			if !filepath.IsLocal(filepath.FromSlash(path)) {
				t.Errorf("%s: invalid local source %q", label, part)
				continue
			}
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
				t.Errorf("%s: source %q does not resolve: %v", label, part, err)
			}
		}
	}
	var transfer struct {
		Entries             []struct{ ID, Target string }
		ComparisonReference struct{ Report, Inventory, Verification string } `json:"comparison_reference"`
		DetectorTransfer    struct{ Report, Verification string }            `json:"detector_transfer"`
	}
	read("internal/distribution/integrations/sources/transfer-manifest.json", &transfer)
	for _, entry := range transfer.Entries {
		check(entry.ID, entry.Target)
	}
	check("comparison report", transfer.ComparisonReference.Report)
	check("comparison inventory", transfer.ComparisonReference.Inventory)
	check("comparison verification", transfer.ComparisonReference.Verification)
	check("detector report", transfer.DetectorTransfer.Report)
	check("detector verification", transfer.DetectorTransfer.Verification)
	var guidance map[string]struct {
		Sources []struct{ URL, Symbol string }
	}
	read("knowledge/data/guidance.json", &guidance)
	for id, guide := range guidance {
		for _, source := range guide.Sources {
			if source.URL != "" || !strings.Contains(source.Symbol, "/") {
				continue
			}
			path, _, _ := strings.Cut(source.Symbol, ":")
			check(id, path)
		}
	}
}
