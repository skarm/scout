//go:build !coreonly && cgo

package maintenance_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/dev/maintenance"
)

func TestKnowledgeRuntimeUsesActualCLIAndScriptedLoopbackProtocol(t *testing.T) {
	t.Setenv("SCOUT_DEVELOPER_CLI_HELPER", "1")
	t.Setenv("GOCOVERDIR", t.TempDir())
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "run")
	var summary bytes.Buffer
	if err := maintenance.CheckKnowledgeRuntimeForTest(t.Context(), binary, output, &summary); err != nil {
		t.Fatalf("actual runtime check failed: %v\n%s", err, &summary)
	}
	if _, err := os.Stat(filepath.Join(output, "summary.json")); err != nil {
		t.Fatal("runtime did not retain its summary")
	}
}

func TestKnowledgeRuntimeRequiresTheActualBoundRun(t *testing.T) {
	t.Setenv("SCOUT_DEVELOPER_CLI_HELPER", "1")
	t.Setenv("GOCOVERDIR", t.TempDir())
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	nativeMaintenanceFile(t, target, "script.py", []byte("import os\nos.system(input())\n"))
	data, _, err := maintenance.InvokeCLIForTest(t.Context(), binary, "scan", "--profile", "standard", "--format", "json", "--", target)
	if err != nil {
		t.Fatal(err)
	}
	document, err := maintenance.DecodeScoutDocumentForTest(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Run.Targets[0].Analysis.Findings) == 0 {
		t.Fatal("actual current scan lost its observations")
	}
	if _, err := maintenance.DecodeScoutDocumentForTest([]byte(`{"schema_version":"0.15","findings":[]}`)); err == nil {
		t.Fatal("flat historical report was reinterpreted as a current run")
	}
}

// This helper executes the actual CLI in a trusted child process. It generates
// no fake reports and never dispatches target content as an executable.
func TestMain(m *testing.M) {
	if os.Getenv("SCOUT_DEVELOPER_CLI_HELPER") == "1" && len(os.Args) > 1 {
		switch os.Args[1] {
		case "scan", "knowledge":
			os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
		}
	}
	os.Exit(m.Run())
}

func nativeMaintenanceFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
