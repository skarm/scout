package cli_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/report"
)

func TestOSVSnapshotCLIUsesCapturedGoVendorVersion(t *testing.T) {
	root := t.TempDir()
	snapshots := filepath.Join(root, "snapshots")
	target := filepath.Join(root, "target")

	for _, dir := range []string{filepath.Join(snapshots, "Go"), filepath.Join(target, "vendor")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(target, "vendor", "modules.txt"),
		[]byte("# example.org/example v1.2.0\nexample.org/example/subpackage\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	zipper := zip.NewWriter(&archive)
	member, err := zipper.Create("GO-test.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(member, `{"id":"GO-test","summary":"Fixture advisory","database_specific":{"severity":"low"},"affected":[{"package":{"ecosystem":"Go","name":"example.org/example"},"versions":["1.2.0"]}]}`); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshots, "Go", "all.zip"), archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var output, stderr bytes.Buffer
	code := cli.Run(t.Context(), []string{"scan", "--profile", "basic", "--osv-snapshot-dir", snapshots, "--format", "json", target}, &output, &stderr)
	if code != 0 {
		t.Fatalf("scan exit=%d: %s", code, stderr.String())
	}

	document := readCLIDocument(t, output.Bytes())
	analysis := document.Run.Targets[0].Analysis
	if analysis.Vulnerabilities.Completeness != report.Complete || len(analysis.Vulnerabilities.Matches) != 1 {
		t.Fatalf("incomplete snapshot lookup: %+v", analysis.Vulnerabilities)
	}

	for _, finding := range analysis.Findings {
		if finding.RuleID == "OSV001" && finding.Severity == report.Low && finding.Location.Path == "vendor/modules.txt" {
			return
		}
	}
	t.Fatalf("advisory severity or source evidence missing: %+v", analysis.Findings)
}
