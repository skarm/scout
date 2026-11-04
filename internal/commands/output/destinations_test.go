package output_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/commands/output"
)

func TestDestinationNamesFollowFilesystemSemantics(t *testing.T) {
	for _, existing := range []bool{false, true} {
		dir := t.TempDir()
		first, second := filepath.Join(dir, "report.json"), filepath.Join(dir, "REPORT.json")
		probe := filepath.Join(dir, "case-probe")
		writeFile(t, probe, "probe")
		_, err := os.Stat(filepath.Join(dir, "CASE-PROBE"))
		foldsCase := err == nil
		if existing {
			writeFile(t, first, "previous report")
		}
		_, err = output.ValidateAll([]string{"", first, second}, nil)
		if (err != nil) != foldsCase {
			t.Fatalf("existing=%t case insensitive=%t error=%v", existing, foldsCase, err)
		}
		if existing {
			assertContents(t, first, "previous report")
		} else if _, err := os.Stat(first); !os.IsNotExist(err) {
			t.Fatal("destination validation created a report")
		}
		matches, err := filepath.Glob(filepath.Join(dir, ".scout-destinations-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("destination probes leaked: %v %v", matches, err)
		}
	}
}

func TestDestinationUnicodeAliasesFollowFilesystemSemantics(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "caf\u00e9.json"), filepath.Join(dir, "cafe\u0301.json")
	writeFile(t, first, "previous report")
	_, aliasErr := os.Stat(second)
	_, err := output.ValidateAll([]string{first, second}, nil)
	if (err != nil) != (aliasErr == nil) {
		t.Fatalf("Unicode alias=%t error=%v", aliasErr == nil, err)
	}
	assertContents(t, first, "previous report")
}

func TestDestinationGroupsRetainInputBoundaries(t *testing.T) {
	dir, input := t.TempDir(), t.TempDir()
	if _, err := output.ValidateAll([]string{filepath.Join(dir, "report"), filepath.Join(input, "other")}, []string{input}); err == nil {
		t.Fatal("multiple destinations bypassed an input boundary")
	}
	if _, err := output.ValidateAll([]string{filepath.Join(dir, "report"), filepath.Join(dir, "report")}, nil); err == nil {
		t.Fatal("duplicate destination accepted")
	}
}
